use futures;
use futures::future::Future;
use hyper;
use hyper::{Method, StatusCode};
use hyper::server::{Http, Request, Response, Service};

struct Diagnostics;

impl Service for Diagnostics {
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
                // Raw JSON - TODO this should be using serde
                response.set_body(r#"{
                    "server": {
                        "application_name": "foo"
                        "application_uri": "urn:foo"
                    },
                    "sessions": [
                        {
                            "id": 1,
                            "client_name": "bar",
                            "client_ip"; "123.333.333.333",
                            "connected_endpoint": {}
                            "subscriptions": [
                                {
                                    "id": 100,
                                    "monitored_items": [
                                    ]
                                }
                            ]
                        }
                    ]
                }"#);
            }
            _ => {
                response.set_status(StatusCode::NotFound);
            }
        }

        Box::new(futures::future::ok(response))
    }
}

pub fn run_http_server() {
    let addr = "127.0.0.1:8585".parse().unwrap();
    let server = Http::new().bind(&addr, || Ok(Diagnostics)).unwrap();
    server.run().unwrap();
}
