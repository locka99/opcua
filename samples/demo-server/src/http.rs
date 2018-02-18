use futures;
use futures::future::Future;
use hyper;
use hyper::{Method, StatusCode};
use hyper::server::{Http, Request, Response, Service};

struct Metrics;

impl Service for Metrics {
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
                response.set_body("TODO webpage");
            }
            /*   (&Method::Post, "/metrics") => {
                   // Raw JSON
               } */
            _ => {
                response.set_status(StatusCode::NotFound);
            }
        }

        Box::new(futures::future::ok(response))
    }
}

pub fn run_http_server() {
    let addr = "127.0.0.1:8585".parse().unwrap();
    let server = Http::new().bind(&addr, || Ok(Metrics)).unwrap();
    server.run().unwrap();
}
