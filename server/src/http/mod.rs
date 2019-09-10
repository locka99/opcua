use std::{
    thread, path::PathBuf,
    sync::{
        Arc, RwLock,
        mpsc,
    },
};

use futures::{Poll, Async};
use futures::future::Future;

use actix_web::{
    actix, http, server, App, Responder, HttpRequest, HttpResponse, fs,
};
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

#[cfg(debug_assertions)]
fn abort(req: &HttpRequest<HttpState>) -> impl Responder {
    let state = req.state();
    // Abort the server from the command
    let mut server_state = state.server_state.write().unwrap();
    server_state.abort();
    HttpResponse::Ok()
        .content_type("text/plain")
        .body("OK")
}

#[cfg(not(debug_assertions))]
fn abort(_: &HttpRequest<HttpState>) -> impl Responder {
    // Abort is only enabled in debug mode
    HttpResponse::Ok()
        .content_type("text/plain")
        .body("NOT IMPLEMENTED")
}

fn metrics(req: &HttpRequest<HttpState>) -> impl Responder {
    use std::ops::Deref;

    let state = req.state();

    // Send metrics data as json
    let json = {
        // Careful with the ordering here to avoid potential deadlock. Metrics are locked
        // several times in scope to avoid deadlocks issues.
        {
            let server_state = state.server_state.read().unwrap();
            let mut server_metrics = state.server_metrics.write().unwrap();
            server_metrics.update_from_server_state(&server_state);
        }

        let connections = state.connections.read().unwrap();
        let connections = connections.deref();
        let mut server_metrics = state.server_metrics.write().unwrap();
        server_metrics.update_from_connections(connections);
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
pub fn run_http_server(address: &str, content_path: &str, server_state: Arc<RwLock<ServerState>>, connections: Arc<RwLock<Connections>>, server_metrics: Arc<RwLock<ServerMetrics>>) {
    let address = String::from(address);
    let base_path = PathBuf::from(content_path);

    let quit_task = HttpQuit { server_state: server_state.clone() };

    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        info!("HTTP server is running on http://{}/ to provide OPC UA server metrics", address);
        let sys = actix::System::new("http-server");
        let addr = server::new(
            move || {
                App::with_state(HttpState {
                    server_state: server_state.clone(),
                    connections: connections.clone(),
                    server_metrics: server_metrics.clone(),
                })
                    .resource("/server/metrics", |r| r.method(http::Method::GET).f(metrics))
                    .resource("/server/abort", |r| r.method(http::Method::GET).f(abort))
                    .handler("/", fs::StaticFiles::new(base_path.clone()).unwrap()
                        .index_file("index.html"))
            })
            .bind(&address).unwrap()
            .start();

        // Give the address info to the quit task
        let _ = tx.send(addr);

        // Run
        let _ = sys.run();
    });

    // Get the address info from the http server thread
    let addr = rx.recv().unwrap();

    // Spawn a tokio task to monitor for quit and to shutdown the http server
    thread::spawn(move || {
        tokio::run(quit_task.map(move |_| {
            info!("HTTP server will be stopped");
            let _ = addr.send(server::StopServer {
                graceful: false
            });
        }));
    });
}
