use std::sync::{Arc, RwLock};
use std::thread;
use std::path::PathBuf;

use futures::{Poll, Async};
use futures::future::Future;

use actix_web::{http, server, App, Responder, HttpRequest, HttpResponse, fs};

use serde_json;

use crate::{
    server::Connections,
    metrics::ServerMetrics,
    state::ServerState,
};

/// This is our metrics service, the thing called to handle requests coming from hyper
#[derive(Clone)]
struct HttpState {
    server_state: Arc<RwLock<ServerState>>,
    connections: Arc<RwLock<Connections>>,
    server_metrics: Arc<RwLock<ServerMetrics>>,
}

fn index(req: &HttpRequest<HttpState>) -> impl Responder {
    fs::NamedFile::open("html/index.html")
}

fn metrics(req: &HttpRequest<HttpState>) -> impl Responder {
    use std::ops::Deref;

    let state = req.state();

    // Send metrics data as json
    let json = {
        let mut server_metrics = state.server_metrics.write().unwrap();
        {
            let server_state = state.server_state.read().unwrap();
            server_metrics.update_from_server_state(&server_state);
        }
        {
            let connections = state.connections.read().unwrap();
            let connections = connections.deref();
            server_metrics.update_from_connections(connections);
        }
        serde_json::to_string_pretty(server_metrics.deref()).unwrap()
    };

    HttpResponse::Ok()
        .content_type("application/json")
        .body(json)
}

struct HttpQuit {
    server_state: Arc<RwLock<ServerState>>
}

impl Future for HttpQuit {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let abort = {
            let server_state = trace_read_lock_unwrap!(self.server_state);
            server_state.is_abort()
        };
        if abort {
            Ok(Async::Ready(()))
        } else {
            Ok(Async::NotReady)
        }
    }
}

/// Runs an http server on the specified binding address, serving out the supplied server metrics
pub fn run_http_server(address: &str, content_path: &str, server_state: Arc<RwLock<ServerState>>, connections: Arc<RwLock<Connections>>, server_metrics: Arc<RwLock<ServerMetrics>>) -> thread::JoinHandle<()> {
    let address = String::from(address);

    let base_path = PathBuf::from(content_path);
    thread::spawn(move || {
        info!("HTTP server is running on http://{}/ to provide OPC UA server metrics", address);
        server::new(
            move || {
                App::with_state(HttpState {
                    server_state: server_state.clone(),
                    connections: connections.clone(),
                    server_metrics: server_metrics.clone(),
                })
                    .resource("/metrics", |r| r.method(http::Method::GET).f(metrics))
                    .handler("/", fs::StaticFiles::new(base_path.clone()).unwrap()
                        .index_file("index.html"))
            })
            .bind(&address).unwrap()
            .run();

        // This polling action will quit the http server when the OPC UA server aborts
        // TODO the server should consume this and terminate
        // let _server_should_quit = HttpQuit { server_state };
        // http_server.run_until(server_should_quit).unwrap();

        info!("HTTP server has stopped");
    })
}
