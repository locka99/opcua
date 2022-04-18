// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

use std::{
    path::PathBuf,
    sync::{mpsc, Arc},
    thread,
};

use actix_web::{actix, fs, http, server, App, HttpRequest, HttpResponse, Responder};
use tokio::time::{interval_at, Duration, Instant};

use crate::sync::*;

use crate::server::{metrics::ServerMetrics, server::Connections, state::ServerState};

/// This is our metrics service, the thing called to handle requests coming from hyper
#[derive(Clone)]
struct HttpState {
    server_state: Arc<RwLock<ServerState>>,
    connections: Arc<RwLock<Connections>>,
    server_metrics: Arc<RwLock<ServerMetrics>>,
}

fn abort(req: &HttpRequest<HttpState>) -> impl Responder {
    if cfg!(debug_assertions) {
        let state = req.state();
        // Abort the server from the command
        let mut server_state = state.server_state.write();
        server_state.abort();
        HttpResponse::Ok().content_type("text/plain").body("OK")
    } else {
        // Abort is only enabled in debug mode
        HttpResponse::Ok()
            .content_type("text/plain")
            .body("NOT IMPLEMENTED")
    }
}

fn metrics(req: &HttpRequest<HttpState>) -> impl Responder {
    use std::ops::Deref;

    let state = req.state();

    // Send metrics data as json
    let json = {
        // Careful with the ordering here to avoid potential deadlock. Metrics are locked
        // several times in scope to avoid deadlocks issues.
        {
            let server_state = state.server_state.read();
            let mut server_metrics = state.server_metrics.write();
            server_metrics.update_from_server_state(&server_state);
        }

        // Take a copy of connections
        let connections = {
            let connections = state.connections.read();
            connections.clone()
        };
        let mut server_metrics = state.server_metrics.write();
        server_metrics.update_from_connections(connections);
        serde_json::to_string_pretty(server_metrics.deref()).unwrap()
    };

    HttpResponse::Ok()
        .content_type("application/json")
        .body(json)
}

/// Runs an http server on the specified binding address, serving out the supplied server metrics
pub fn run_http_server(
    address: &str,
    content_path: &str,
    server_state: Arc<RwLock<ServerState>>,
    connections: Arc<RwLock<Connections>>,
    server_metrics: Arc<RwLock<ServerMetrics>>,
) {
    let address = String::from(address);
    let base_path = PathBuf::from(content_path);

    let (tx, rx) = mpsc::channel();

    let server_state_http = server_state.clone();
    thread::spawn(move || {
        info!(
            "HTTP server is running on http://{}/ to provide OPC UA server metrics",
            address
        );
        let sys = actix::System::new("http-server");
        let addr = server::new(move || {
            App::with_state(HttpState {
                server_state: server_state_http.clone(),
                connections: connections.clone(),
                server_metrics: server_metrics.clone(),
            })
            .resource("/server/metrics", |r| {
                r.method(http::Method::GET).f(metrics)
            })
            .resource("/server/abort", |r| r.method(http::Method::GET).f(abort))
            .handler(
                "/",
                fs::StaticFiles::new(base_path.clone())
                    .unwrap()
                    .index_file("index.html"),
            )
        })
        .bind(&address)
        .unwrap()
        .start();

        // Give the address info to the quit task
        let _ = tx.send(addr);

        // Run
        let _ = sys.run();
    });

    // Get the address info from the http server thread
    let addr = rx.recv().unwrap();

    // Spawn tokio to monitor for quit and to shutdown the http server
    thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async move {
                let mut timer = interval_at(Instant::now(), Duration::from_secs(1));
                loop {
                    {
                        let server_state = trace_read_lock!(server_state);
                        if server_state.is_abort() {
                            let _ = addr.send(server::StopServer { graceful: false });
                            info!("HTTP server will be stopped");
                            break;
                        }
                    }
                    timer.tick().await;
                }
            });
    });
}
