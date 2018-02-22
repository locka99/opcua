use futures;
use futures::future::Future;
use hyper;
use hyper::{Method, StatusCode};
use hyper::header::ContentType;
use hyper::server::{Http, NewService, Request, Response, Service};
use opcua_server::server_metrics::ServerMetrics;
use serde_json;
use std;
use std::sync::{Arc, Mutex};

#[derive(Serialize)]
struct Metrics {
    pub server: Server,
    pub sessions: Vec<Session>,
}

#[derive(Serialize)]
struct Server {
    pub application_name: String,
    pub application_uri: String,
}

#[derive(Serialize)]
struct Session {
    pub id: u32,
    pub client_name: String,
    pub client_ip: String,
    pub subscriptions: Vec<Subscription>,
}

#[derive(Serialize)]
struct Subscription {
    id: u32,
}

/// This is our metrics service, the thing called to handle requests coming from hyper
struct MetricsService {
    server_metrics: Arc<Mutex<ServerMetrics>>
}

impl MetricsService {
    fn new(server_metrics: Arc<Mutex<ServerMetrics>>) -> MetricsService {
        MetricsService {
            server_metrics
        }
    }

    fn fetch_metrics(&self) -> Metrics {
        // Sample metrics
        Metrics {
            server: Server {
                application_name: String::from("server name"),
                application_uri: String::from("urn:server"),
            },
            sessions: vec![
                Session {
                    id: 1,
                    client_name: String::from("bar"),
                    client_ip: String::from("123.0.0.1"),
                    subscriptions: vec![
                        Subscription {
                            id: 100,
                        }
                    ],
                }
            ],
        }
    }
}

impl Service for MetricsService {
    // boilerplate hooking up hyper's server types
    type Request = Request;
    type Response = Response;
    type Error = hyper::Error;

    // The future representing the eventual Response the call will resolve to
    type Future = Box<Future<Item=Self::Response, Error=Self::Error>>;

    fn call(&self, req: Request) -> Self::Future {
        let mut response = Response::new();
        match (req.method(), req.path()) {
            (&Method::Get, "/") => {
                let content = include_str!("index.html");
                response.set_body(content);
            }
            (&Method::Get, "/metrics") => {
                // Send metrics data as json
                let metrics = self.fetch_metrics();
                response.headers_mut().set(ContentType::json());
                response.set_body(serde_json::to_string(&metrics).unwrap());
            }
            _ => {
                response.set_status(StatusCode::NotFound);
            }
        }
        Box::new(futures::future::ok(response))
    }
}

pub fn run_http_server(server_metrics: Arc<Mutex<ServerMetrics>>) {
    /*    let addr = "127.0.0.1:8585".parse().unwrap();
        let server = Http::new().bind(&addr, || {
            let metrics_service = MetricsService::new(server_metrics);
            Ok(metrics_service)
        }).unwrap();
        server.run().unwrap(); */
}
