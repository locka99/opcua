extern crate actix;
extern crate actix_web;

use actix::prelude::*;
use actix_web::server::HttpServer;
use actix_web::{fs, http, ws, App, Error, HttpRequest, HttpResponse};

struct State {}

struct WebSocket {}

impl Actor for WebSocket {
    type Context = ws::WebsocketContext<Self, State>;

    /// Method is called on actor start. We start the heartbeat process here.
    fn started(&mut self, ctx: &mut Self::Context) {}
}

/// Handler for `ws::Message`
impl StreamHandler<ws::Message, ws::ProtocolError> for WebSocket {
    fn handle(&mut self, msg: ws::Message, ctx: &mut Self::Context) {
        // process websocket messages
        println!("WS: {:?}", msg);
        match msg {
            ws::Message::Ping(msg) => {
                ctx.pong(&msg);
            }
            ws::Message::Pong(_) => {}
            ws::Message::Text(text) => ctx.text(text),
            ws::Message::Binary(bin) => ctx.binary(bin),
            ws::Message::Close(_) => {
                ctx.stop();
            }
        }
    }
}

fn ws_index(r: &HttpRequest<State>) -> Result<HttpResponse, Error> {
    ws::start(r, WebSocket {})
}

fn main() {
    let base_path = "./html";
    let address = "127.0.0.1:8686";
    HttpServer::new(move || {
        let state = State {};
        App::with_state(state)
            // Websocket
            .resource("/ws/", |r| r.method(http::Method::GET).f(ws_index))
            // Static content
            .handler("/", fs::StaticFiles::new(base_path.clone()).unwrap()
                .index_file("index.html"))
    }).bind(address)
        .unwrap()
        .run();
}