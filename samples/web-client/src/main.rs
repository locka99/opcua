use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use ::actix::prelude::*;
use actix_web::server::HttpServer;
use actix_web::{fs, http, ws, App, Error, HttpRequest, HttpResponse};

use opcua_client::prelude::*;

struct State {}

struct WebSocket {}

impl Actor for WebSocket {
    type Context = ws::WebsocketContext<Self, State>;

    /// Method is called on actor start. We start the heartbeat process here.
    fn started(&mut self, _ctx: &mut Self::Context) {}
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
    // Optional - enable OPC UA logging
    opcua_console_logging::init();

    // Kick off http server on a separate thread
    http_spawn();

    // Run opcua server (on this thread). Theoretically, every single web socket could have its own
    // client which might make more sense (possibly). This way allows them to share the connection,
    // and subscript their interest to it.
    opcua_run();
}

fn http_spawn() {
    use std::thread;

    let _ = thread::spawn(|| {
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
    });
}

fn opcua_run() {
    // Use the sample client config to set up a client. The sample config has a number of named
    // endpoints one of which is marked as the default.
    let config_file = "../client.conf";
    let mut client = Client::new(ClientConfig::load(&PathBuf::from(config_file)).unwrap());
    if let Ok(session) = client.connect_and_activate(None) {
        let result = subscription_loop(session);
        if let Err(result) = result {
            println!("ERROR: Got an error while performing action - {}", result);
        }
    }
}

fn nodes_to_monitor() -> Vec<ReadValueId> {
    vec![
        ReadValueId::from(NodeId::new(2, "v1")),
        ReadValueId::from(NodeId::new(2, "v2")),
        ReadValueId::from(NodeId::new(2, "v3")),
        ReadValueId::from(NodeId::new(2, "v4")),
    ]
}

fn publish_value(read_value_id: &ReadValueId, data_value: &DataValue) {
    // TODO here we go through every open web socket, publishing a change event
    println!("publish_value");
}


fn subscription_loop(session: Arc<RwLock<Session>>) -> Result<(), StatusCode> {
    // Create a subscription
    println!("Creating subscription");

    // This scope is important - we don't want to session to be locked when the code hits the
    // loop below
    {
        let mut session = session.write().unwrap();

        // Creates our subscription
        let subscription_id = session.create_subscription(2000.0, 10, 30, 0, 0, true, DataChangeCallback::new(|items| {
            println!("Data change from server:");
            items.iter().for_each(|item| {
                publish_value(&item.item_to_monitor(), &item.value());
            });
        }))?;
        println!("Created a subscription with id = {}", subscription_id);

        // Create some monitored items
        let read_nodes = nodes_to_monitor();
        let items_to_create: Vec<MonitoredItemCreateRequest> = read_nodes.into_iter().map(|read_node| {
            MonitoredItemCreateRequest::new(read_node, MonitoringMode::Reporting, MonitoringParameters::default())
        }).collect();
        let _ = session.create_monitored_items(subscription_id, &items_to_create)?;
    }

    // Loops forever. The publish thread will call the callback with changes on the variables
    loop {
        let mut session = session.write().unwrap();
        // Break the loop if connection goes down
        if !session.is_connected() {
            println!("Connection to server broke, so terminating");
            break;
        }
        // Main thread has nothing to do - just wait for publish events to roll in
        session.poll();
    }

    Ok(())
}