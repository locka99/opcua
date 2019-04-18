#[macro_use]
extern crate serde_derive;

use std::{
    sync::{mpsc, Arc, RwLock},
    time::{Duration, Instant},
    str::FromStr,
};

use clap::{self, value_t_or_exit};
use serde_json;

use actix_web::{
    fs, http, ws,
    App, Error, HttpRequest, HttpResponse,
    actix::{StreamHandler, Actor, ActorContext, Message, Running, AsyncContext, Handler},
    server::HttpServer,
};

use opcua_client::prelude::*;

fn main() {
    // Read command line arguments
    let matches = clap::App::new("Web Client")
        .arg(clap::Arg::with_name("http-port")
            .long("http-port")
            .help("The port number that this web server will run from")
            .default_value("8686")
            .takes_value(true)
            .required(false))
        .get_matches();
    let http_port = value_t_or_exit!(matches, "http-port", u16);

    // Optional - enable OPC UA logging
    opcua_console_logging::init();

    // Run the http server
    run_server(format!("127.0.0.1:{}", http_port));
}

#[derive(Serialize)]
struct DataChangeEvent {
    pub node_id: String,
    pub attribute_id: u32,
    pub value: DataValue,
}

impl Message for DataChangeEvent {
    type Result = ();
}

#[derive(Serialize, Message)]
enum Event {
    ConnectionStatusChangeEvent(bool),
    DataChangeEvent(Vec<DataChangeEvent>),
}

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
const CLIENT_TIMEOUT: Duration = Duration::from_secs(10);

/// This is an Actix actor. The fields are the state maintained by the actor
struct OPCUASession {
    /// Last ping received from client
    hb: Instant,
    /// The OPC UA client
    client: Client,
    /// The OPC UA session
    session: Option<Arc<RwLock<Session>>>,
    /// A sender that the session can use to terminate the corresponding OPC UA session
    session_tx: Option<mpsc::Sender<SessionCommand>>,
}

impl Actor for OPCUASession {
    type Context = ws::WebsocketContext<Self, HttpServerState>;

    /// Method is called on actor start. We start the heartbeat process here.
    fn started(&mut self, ctx: &mut Self::Context) {
        // Heartbeat
        self.hb(ctx);
    }

    fn stopping(&mut self, ctx: &mut Self::Context) -> Running {
        // Stop the OPC UA session
        self.disconnect(ctx);
        Running::Stop
    }
}

/// Handle messages from chat server, we simply send it to peer websocket
impl Handler<Event> for OPCUASession {
    type Result = ();

    fn handle(&mut self, msg: Event, ctx: &mut Self::Context) {
        // This is where we receive OPC UA events. It is here they are turned into JSON
        // and sent to the attached web socket.
        println!("Received event {}", match &msg {
            Event::ConnectionStatusChangeEvent(ref connected) => format!("ConnectionStatusChangeEvent({})", connected),
            Event::DataChangeEvent(_) => "DataChangeEvent".to_string()
        });
        ctx.text(serde_json::to_string(&msg).unwrap())
    }
}

/// Handler for `ws::Message`
impl StreamHandler<ws::Message, ws::ProtocolError> for OPCUASession {
    fn handle(&mut self, msg: ws::Message, ctx: &mut Self::Context) {
        // process websocket messages
        println!("WS: {:?}", msg);
        match msg {
            ws::Message::Ping(msg) => {
                self.hb = Instant::now();
                ctx.pong(&msg);
            }
            ws::Message::Pong(_) => {
                self.hb = Instant::now();
            }
            ws::Message::Text(msg) => {
                let msg = msg.trim();
                if msg.starts_with("connect ") {
                    self.connect(ctx, &msg[8..]);
                } else if msg.eq("disconnect") {
                    self.disconnect(ctx);
                } else if msg.starts_with("subscribe ") {
                    // Node ids are comma separated
                    let node_ids: Vec<String> = msg[10..].split(",").map(|s| s.to_string()).collect();
                    self.subscribe(ctx, node_ids);
                }
            }
            ws::Message::Binary(bin) => ctx.binary(bin),
            ws::Message::Close(_) => {
                ctx.stop();
            }
        }
    }
}

impl OPCUASession {
    fn hb(&self, ctx: &mut <Self as Actor>::Context) {
        // Run a ping-pong timer
        ctx.run_interval(HEARTBEAT_INTERVAL, |act, ctx| {
            if Instant::now().duration_since(act.hb) > CLIENT_TIMEOUT {
                ctx.stop();
            } else {
                ctx.ping("");
            }
        });
    }

    fn connect(&mut self, ctx: &mut <Self as Actor>::Context, opcua_url: &str) {
        self.disconnect(ctx);

        let addr = ctx.address();
        let connected = match self.client.connect_to_endpoint((opcua_url, SecurityPolicy::None.to_str(), MessageSecurityMode::None, UserTokenPolicy::anonymous()), IdentityToken::Anonymous) {
            Ok(session) => {
                {
                    let mut session = session.write().unwrap();
                    let addr_for_connection_status_change = addr.clone();
                    session.set_connection_status_callback(ConnectionStatusCallback::new(move |connected| {
                        println!("Connection status has changed to {}", if connected { "connected" } else { "disconnected" });
                        addr_for_connection_status_change.do_send(Event::ConnectionStatusChangeEvent(connected));
                    }));
                    session.set_session_closed_callback(SessionClosedCallback::new(|status| {
                        println!("Session has been closed, status = {}", status);
                    }));
                }
                self.session = Some(session);
                true
            }
            Err(err) => {
                println!("ERROR: Got an error while trying to connect to session - {}", err);
                false
            }
        };
        addr.do_send(Event::ConnectionStatusChangeEvent(connected));
    }

    fn disconnect(&mut self, _ctx: &mut <Self as Actor>::Context) {
        if let Some(ref mut session) = self.session {
            let mut session = session.write().unwrap();
            if session.is_connected() {
                session.disconnect();
            }
        }
        if let Some(ref tx) = self.session_tx {
            let _ = tx.send(SessionCommand::Stop);
        }
        self.session = None;
        self.session_tx = None;
    }

    fn subscribe(&mut self, ctx: &mut <Self as Actor>::Context, node_ids: Vec<String>) {
        if let Some(ref mut session) = self.session {
            // Create a subscription
            println!("Creating subscription");

            // This scope is important - we don't want to session to be locked when the code hits the
            // loop below
            {
                let mut session = session.write().unwrap();

                // Creates our subscription
                let addr_for_datachange = ctx.address();
                let subscription_id = session.create_subscription(500.0, 10, 30, 0, 0, true, DataChangeCallback::new(move |items| {
                    // Changes will be turned into a list of change events that sent to corresponding
                    // web socket to be sent to the client.
                    let changes = items.iter().map(|item| {
                        let item_to_monitor = item.item_to_monitor();
                        DataChangeEvent {
                            node_id: item_to_monitor.node_id.clone().into(),
                            attribute_id: item_to_monitor.attribute_id,
                            value: item.value().clone(),
                        }
                    }).collect::<Vec<_>>();

                    // Send the changes to the websocket session
                    addr_for_datachange.do_send(Event::DataChangeEvent(changes));
                })).unwrap();
                println!("Created a subscription with id = {}", subscription_id);
                // Create some monitored items
                let items_to_create: Vec<MonitoredItemCreateRequest> = node_ids.iter().map(|node_id| {
                    let node_id = NodeId::from_str(node_id).unwrap(); // Trust client to not break this
                    MonitoredItemCreateRequest::new(node_id.into(), MonitoringMode::Reporting, MonitoringParameters::default())
                }).collect();
                let _results = session.create_monitored_items(subscription_id, TimestampsToReturn::Both, &items_to_create);
            }
        }

        if self.session_tx.is_none() {
            // Runs the session asynchronously.
            self.session_tx = Some(Session::run_async(self.session.as_ref().unwrap().clone()));
        }
    }
}

/// Handler for creating a new websocket
fn ws_create_request(r: &HttpRequest<HttpServerState>) -> Result<HttpResponse, Error> {
    let client = ClientBuilder::new()
        .application_name("WebSocketClient")
        .application_uri("urn:WebSocketClient")
        .trust_server_certs(true)
        .create_sample_keypair(true)
        .session_retry_limit(3)
        .client().unwrap();

    ws::start(r, OPCUASession {
        hb: Instant::now(),
        client,
        session: None,
        session_tx: None,
    })
}

#[derive(Clone)]
struct HttpServerState {}

fn run_server(address: String) {
    let base_path = "./html";

    HttpServer::new(move || {
        let state = HttpServerState {};
        App::with_state(state)
            // Websocket
            .resource("/ws/", |r| r.method(http::Method::GET).f(ws_create_request))
            // Static content
            .handler("/", fs::StaticFiles::new(base_path.clone()).unwrap()
                .index_file("index.html"))
    }).bind(address)
        .unwrap()
        .run();
}
