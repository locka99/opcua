extern crate actix_web;

use actix_web::server::HttpServer;
use actix_web::{fs, http, ws, App, Error, HttpRequest, HttpResponse};

struct State {}

fn main() {
    let base_path = "./html";
    let address = "127.0.0.1:8686";
    HttpServer::new(move || {
        // Websocket sessions state
        let state = State {};

        App::with_state(state)
            // redirect to websocket.html
            // .resource("/metrics", |r| r.method(http::Method::GET).f(metrics))
            .handler("/", fs::StaticFiles::new(base_path.clone()).unwrap()
                .index_file("index.html"))
    }).bind(address)
        .unwrap()
        .run();
}