use std::sync::{Arc, RwLock};
use std::thread;

use futures::{Poll, Async};
use futures::future::Future;
use hyper;
use hyper::{Server, Request, Response, Body, Method, StatusCode};
use hyper::service::service_fn_ok;
use hyper::rt;
use serde_json;

use server::Connections;
use metrics::ServerMetrics;
use state::ServerState;

/// This is our metrics service, the thing called to handle requests coming from hyper
#[derive(Clone)]
struct HttpState {
    server_state: Arc<RwLock<ServerState>>,
    connections: Arc<RwLock<Connections>>,
    server_metrics: Arc<RwLock<ServerMetrics>>,
}

fn http(state: &HttpState, req: Request<Body>) -> Response<Body> {
    let mut builder = Response::builder();
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/") => {
            let content = include_str!("index.html");
            builder
                .body(content.into())
                .unwrap()
        }
        (&Method::GET, "/metrics") => {
            use std::ops::Deref;
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
            builder
                .header(hyper::header::CONTENT_TYPE, "text/json")
                .body(json.into())
                .unwrap()
        }
        _ => {
            builder
                .status(StatusCode::NOT_FOUND)
                .body(Body::empty())
                .unwrap()
        }
    }
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
pub fn run_http_server(address: &str, server_state: Arc<RwLock<ServerState>>, connections: Arc<RwLock<Connections>>, server_metrics: Arc<RwLock<ServerMetrics>>) -> thread::JoinHandle<()> {
    let address = address.parse().unwrap();
    thread::spawn(move || {
        // This polling action will quit the http server when the OPC UA server aborts
        let server_should_quit = HttpQuit { server_state: server_state.clone() };

        let http_state = HttpState {
            server_state,
            connections,
            server_metrics,
        };

        info!("HTTP server is running on {} to provide OPC UA server metrics", address);
        let new_service = move || {
            let http_state = http_state.clone();
            service_fn_ok(move |req| http(&http_state, req))
        };

        let http_server = Server::bind(&address)
            .serve(new_service)
            .map_err(|e| error!("Http server error: {}", e));

        rt::run(http_server);

        // http_server.run_until(server_should_quit).unwrap();

        info!("HTTP server has stopped");
    })
}
