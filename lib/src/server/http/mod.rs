// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

use std::{path::PathBuf, sync::Arc, thread};

use actix_files as fs;
use actix_web::{web, App, HttpResponse, HttpServer, Responder, Result};
use tokio::runtime::Handle;

use crate::sync::*;

use crate::server::{metrics::ServerMetrics, server::Connections, state::ServerState};

/// This is our metrics service, the thing called to handle requests coming from hyper
#[derive(Clone)]
struct AppState {
    server_state: Arc<RwLock<ServerState>>,
    connections: Arc<RwLock<Connections>>,
    server_metrics: Arc<RwLock<ServerMetrics>>,
    base_path: Arc<RwLock<PathBuf>>,
}

async fn index(data: web::Data<AppState>) -> Result<fs::NamedFile> {
    let base_path = data.base_path.read();
    let mut index_path = base_path.clone();
    index_path.push("index.html");
    debug!("Resolving index.html to location {}", index_path.display());
    Ok(fs::NamedFile::open(index_path)?)
}

async fn abort(data: web::Data<AppState>) -> impl Responder {
    if cfg!(debug_assertions) {
        // Abort the server from the command
        let mut server_state = data.server_state.write();
        server_state.abort();
        HttpResponse::Ok().content_type("text/plain").body("OK")
    } else {
        // Abort is only enabled in debug mode
        HttpResponse::Ok()
            .content_type("text/plain")
            .body("NOT IMPLEMENTED")
    }
}

async fn metrics(data: web::Data<AppState>) -> impl Responder {
    use std::ops::Deref;

    // Send metrics data as json
    let json = {
        // Careful with the ordering here to avoid potential deadlock. Metrics are locked
        // several times in scope to avoid deadlocks issues.
        {
            let server_state = data.server_state.read();
            let mut server_metrics = data.server_metrics.write();
            server_metrics.update_from_server_state(&server_state);
        }

        // Take a copy of connections
        let connections = {
            let connections = data.connections.read();
            connections.clone()
        };
        let mut server_metrics = data.server_metrics.write();
        server_metrics.update_from_connections(connections);
        serde_json::to_string_pretty(server_metrics.deref()).unwrap()
    };

    HttpResponse::Ok()
        .content_type("application/json")
        .body(json)
}

/// Runs an http server on the specified binding address, serving out the supplied server metrics
pub fn run_http_server(
    handle: &Handle,
    address: &str,
    content_path: &str,
    server_state: Arc<RwLock<ServerState>>,
    connections: Arc<RwLock<Connections>>,
    server_metrics: Arc<RwLock<ServerMetrics>>,
) {
    let address = String::from(address);
    let base_path = PathBuf::from(content_path);
    let server_state_http = server_state.clone();

    // Getting this working was very painful since Actix HttpServer does not implement Send trait, so the
    // code has to run on a single thread, but also async and through Tokio.

    let runtime_handle = handle.clone();
    thread::spawn(move || {
        info!(
            "HTTP server is running on http://{}/ to provide OPC UA server metrics",
            address
        );

        let local = tokio::task::LocalSet::new();
        local.spawn_local(async move {
            // Spawns a new HTTP server
            if let Ok(server) = HttpServer::new(move || {
                App::new()
                    .app_data(web::Data::new(AppState {
                        server_state: server_state_http.clone(),
                        connections: connections.clone(),
                        server_metrics: server_metrics.clone(),
                        base_path: Arc::new(RwLock::new(base_path.clone())),
                    }))
                    .route("/server/metrics", web::get().to(metrics))
                    .route("/server/abort", web::get().to(abort))
                    .route("/", web::get().to(index))
            })
            .bind(&address)
            {
                let _ = server.run().await;
            } else {
                error!("Could not start HTTP server");
            }
        });
        runtime_handle.block_on(local);
        debug!("HTTP server has terminated");
    });
}
