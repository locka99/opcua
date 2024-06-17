// OPCUA for Rust
// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

#[macro_use]
extern crate serde_derive;

use std::{
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};

use actix_web::{
    actix::{Actor, ActorContext, AsyncContext, Handler, Message, Running, StreamHandler},
    fs, http,
    server::HttpServer,
    ws, App, Error, HttpRequest, HttpResponse,
};
use futures_util::StreamExt;
use opcua::{
    client::{
        Client, ClientBuilder, DataChangeCallback, EventCallback, IdentityToken, Session,
        SessionPollResult,
    },
    crypto::SecurityPolicy,
    types::{
        AttributeId, ContentFilter, ContentFilterElement, DataValue, EventFilter, ExtensionObject,
        FilterOperator, MessageSecurityMode, MonitoredItemCreateRequest, NodeId, ObjectId,
        ObjectTypeId, Operand, QualifiedName, ReferenceTypeId, SimpleAttributeOperand,
        TimestampsToReturn, UAString, UserTokenPolicy, Variant,
    },
};
use tokio::{pin, runtime::Runtime};

struct Args {
    help: bool,
    http_port: u16,
}

impl Args {
    pub fn parse_args() -> Result<Args, Box<dyn std::error::Error>> {
        let mut args = pico_args::Arguments::from_env();
        Ok(Args {
            help: args.contains(["-h", "--help"]),
            http_port: args
                .opt_value_from_str("--http-port")?
                .unwrap_or(DEFAULT_HTTP_PORT),
        })
    }

    pub fn usage() {
        println!(
            r#"Web Client
Usage:
  -h, --help   Show help
  --http-port  The port number that this web server will run from (default: {})"#,
            DEFAULT_HTTP_PORT
        );
    }
}

const DEFAULT_HTTP_PORT: u16 = 8686;

fn main() -> Result<(), ()> {
    let args = Args::parse_args().map_err(|_| Args::usage())?;
    if args.help {
        Args::usage();
        return Ok(());
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    // Optional - enable OPC UA logging
    opcua::console_logging::init();
    // Run the http server
    run_server(format!("127.0.0.1:{}", args.http_port), Arc::new(runtime));
    Ok(())
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
    ConnectionStatusChange(bool),
    DataChange(Vec<DataChangeEvent>),
    Event(Option<Vec<Variant>>),
}

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
const CLIENT_TIMEOUT: Duration = Duration::from_secs(20);

/// This is an Actix actor. The fields are the state maintained by the actor
struct OPCUASession {
    /// Last ping received from client
    hb: Instant,
    /// The OPC UA client
    client: Client,
    /// The OPC UA session
    session: Option<Arc<Session>>,
    /// The tokio runtime
    rt: Arc<Runtime>,
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
        let rt = self.rt.clone();
        rt.block_on(self.disconnect(ctx));
        Running::Stop
    }
}

/// Handle messages from chat server, we simply send it to peer websocket
impl Handler<Event> for OPCUASession {
    type Result = ();

    fn handle(&mut self, msg: Event, ctx: &mut Self::Context) {
        // This is where we receive OPC UA events. It is here they are turned into JSON
        // and sent to the attached web socket.
        println!(
            "Received event {}",
            match &msg {
                Event::ConnectionStatusChange(ref connected) =>
                    format!("ConnectionStatusChangeEvent({})", connected),
                Event::DataChange(_) => "DataChangeEvent".to_string(),
                Event::Event(_) => "Event".to_string(),
            }
        );
        ctx.text(serde_json::to_string(&msg).unwrap())
    }
}

/// Handler for `ws::Message`
impl StreamHandler<ws::Message, ws::ProtocolError> for OPCUASession {
    fn handle(&mut self, msg: ws::Message, ctx: &mut Self::Context) {
        // process websocket messages
        println!("WS: {:?}", msg);
        let rt = self.rt.clone();
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
                if let Some(msg) = msg.strip_prefix("connect ") {
                    rt.block_on(self.connect(ctx, msg));
                } else if msg.eq("disconnect") {
                    rt.block_on(self.disconnect(ctx));
                } else if let Some(msg) = msg.strip_prefix("subscribe ") {
                    // Node ids are comma separated
                    let node_ids: Vec<String> = msg.split(',').map(|s| s.to_string()).collect();
                    rt.block_on(self.subscribe(ctx, node_ids));
                    println!("subscription complete");
                } else if let Some(msg) = msg.strip_prefix("add_event ") {
                    let args: Vec<String> = msg.split(',').map(|s| s.to_string()).collect();
                    rt.block_on(self.add_event(ctx, args));
                    println!("add event complete");
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
                println!("Context is stopping for client timeout");
                ctx.stop();
            } else {
                ctx.ping("");
            }
        });
    }

    async fn connect(&mut self, ctx: &mut <Self as Actor>::Context, opcua_url: &str) {
        let _ = self.disconnect(ctx).await;

        let addr = ctx.address();
        let connected = match self
            .client
            .new_session_from_endpoint(
                (
                    opcua_url,
                    SecurityPolicy::None.to_str(),
                    MessageSecurityMode::None,
                    UserTokenPolicy::anonymous(),
                ),
                IdentityToken::Anonymous,
            )
            .await
        {
            Ok((session, event_loop)) => {
                let addr_for_connection_status_change = addr.clone();
                tokio::task::spawn(async move {
                    let stream = event_loop.enter();
                    pin!(stream);
                    while let Some(msg) = stream.next().await {
                        match msg {
                            Ok(SessionPollResult::Reconnected(_)) => {
                                println!("Session is now connected");
                                addr_for_connection_status_change
                                    .do_send(Event::ConnectionStatusChange(true));
                            }
                            Ok(SessionPollResult::ConnectionLost(s)) => {
                                println!("Lost connection with status: {s}");
                                addr_for_connection_status_change
                                    .do_send(Event::ConnectionStatusChange(false));
                            }
                            Err(e) => {
                                println!("Session has been closed fatally, status = {}", e);
                            }
                            _ => {}
                        }
                    }
                });
                self.session = Some(session.clone());
                session.wait_for_connection().await
            }
            Err(err) => {
                println!(
                    "ERROR: Got an error while trying to connect to session - {}",
                    err
                );
                false
            }
        };

        addr.do_send(Event::ConnectionStatusChange(connected));
    }

    async fn disconnect(&mut self, _ctx: &mut <Self as Actor>::Context) {
        if let Some(ref session) = self.session {
            let _ = session.disconnect().await;
        }
        self.session = None;
    }

    fn lhs_operand(op: &str) -> Operand {
        Operand::simple_attribute(
            ReferenceTypeId::Organizes,
            op,
            AttributeId::Value,
            UAString::null(),
        )
    }

    fn rhs_operand(op: &str, lhs: &str) -> Option<Operand> {
        if op.is_empty() {
            None
        } else if op.contains('/') {
            // Treat as a browse path to an event
            // ObjectTypeId::BaseEventType
            let base_event_type = NodeId::from((0, 2041));
            Some(Operand::simple_attribute(
                base_event_type,
                op,
                AttributeId::Value,
                UAString::null(),
            ))
        } else {
            // A couple of lhs values should be parsed to types other than a string
            match lhs {
                // "SourceNode" => NodeId::from_str(op).map(|v| Operand::literal(v)).ok(),
                // "Severity" => u16::from_str(op).map(|v| Operand::literal(v)).ok(),
                op => Some(Operand::literal(op)),
            }
        }
    }

    async fn add_event(&mut self, ctx: &mut <Self as Actor>::Context, args: Vec<String>) {
        if args.len() != 3 {
            return;
        }
        let event_node_id = args.first().unwrap();
        let where_clause = args.get(1).unwrap();
        let select_criteria = args.get(2).unwrap();

        if let Some(ref mut session) = self.session {
            let event_node_id = NodeId::from_str(event_node_id);
            if event_node_id.is_err() {
                return;
            }
            let event_node_id = event_node_id.unwrap();

            let where_clause = if where_clause.is_empty() {
                ContentFilter { elements: None }
            } else {
                let where_parts = where_clause.split('|').collect::<Vec<_>>();
                if where_parts.len() != 3 {
                    println!("Where clause has wrong number of parts");
                    return;
                }
                // Left and right operands
                let lhs_str = where_parts.first().unwrap();
                let operator = where_parts.get(1).unwrap();
                let rhs_str = where_parts.get(2).unwrap();

                let lhs = Self::lhs_operand(lhs_str);
                let rhs = Self::rhs_operand(rhs_str, lhs_str);
                if rhs.is_none() {
                    return;
                }

                // Operator
                let operator = match *operator {
                    "eq" => FilterOperator::Equals,
                    "lt" => FilterOperator::LessThan,
                    "gt" => FilterOperator::GreaterThan,
                    "lte" => FilterOperator::LessThanOrEqual,
                    "gte" => FilterOperator::GreaterThanOrEqual,
                    "like" => FilterOperator::Like,
                    _ => {
                        // Unsupported
                        println!("Unsupported operator");
                        return;
                    }
                };

                // Where clause
                ContentFilter {
                    elements: Some(vec![ContentFilterElement::from((
                        operator,
                        vec![lhs, rhs.unwrap()],
                    ))]),
                }
            };

            // Select clauses
            let select_clauses = Some(
                select_criteria
                    .split(',')
                    .map(|s| SimpleAttributeOperand {
                        type_definition_id: ObjectTypeId::BaseEventType.into(),
                        browse_path: Some(vec![QualifiedName::from(s)]),
                        attribute_id: AttributeId::Value as u32,
                        index_range: UAString::null(),
                    })
                    .collect(),
            );

            let event_filter = EventFilter {
                select_clauses,
                where_clause,
            };

            let addr_for_events = ctx.address();
            let event_callback = EventCallback::new(move |evt, _item| {
                // Handle events
                addr_for_events.do_send(Event::Event(evt.clone()));
            });

            // create a subscription containing events
            if let Ok(subscription_id) = session
                .create_subscription(
                    Duration::from_millis(500),
                    100,
                    300,
                    0,
                    0,
                    true,
                    event_callback,
                )
                .await
            {
                // Monitor the item for events
                let mut item_to_create: MonitoredItemCreateRequest = event_node_id.into();
                item_to_create.item_to_monitor.attribute_id = AttributeId::EventNotifier as u32;
                item_to_create.requested_parameters.filter = ExtensionObject::from_encodable(
                    ObjectId::EventFilter_Encoding_DefaultBinary,
                    &event_filter,
                );
                if let Ok(result) = session
                    .create_monitored_items(
                        subscription_id,
                        TimestampsToReturn::Both,
                        vec![item_to_create],
                    )
                    .await
                {
                    println!("Result of subscribing to event = {:?}", result);
                } else {
                    println!("Cannot create monitored event!");
                }
            } else {
                println!("Cannot create event subscription!");
            }
        }
    }

    async fn subscribe(&mut self, ctx: &mut <Self as Actor>::Context, node_ids: Vec<String>) {
        if let Some(ref mut session) = self.session {
            // Create a subscription
            println!("Creating subscription");

            // Creates our subscription
            let addr_for_datachange = ctx.address();

            let data_change_callback = DataChangeCallback::new(move |data_value, item| {
                // Changes will be turned into a list of change events that sent to corresponding
                // web socket to be sent to the client.
                let item_to_monitor = item.item_to_monitor();
                let change = DataChangeEvent {
                    node_id: item_to_monitor.node_id.clone().into(),
                    attribute_id: item_to_monitor.attribute_id,
                    value: data_value,
                };
                // Send the changes to the websocket session
                addr_for_datachange.do_send(Event::DataChange(vec![change]));
            });

            if let Ok(subscription_id) = session
                .create_subscription(
                    Duration::from_millis(500),
                    10,
                    30,
                    0,
                    0,
                    true,
                    data_change_callback,
                )
                .await
            {
                println!("Created a subscription with id = {}", subscription_id);
                // Create some monitored items
                let items_to_create: Vec<MonitoredItemCreateRequest> = node_ids
                    .iter()
                    .map(|node_id| {
                        let node_id = NodeId::from_str(node_id).unwrap(); // Trust client to not break this
                        node_id.into()
                    })
                    .collect();
                if let Ok(_results) = session
                    .create_monitored_items(
                        subscription_id,
                        TimestampsToReturn::Both,
                        items_to_create,
                    )
                    .await
                {
                    println!("Created monitored items");
                } else {
                    println!("Cannot create monitored items!");
                }
            } else {
                println!("Cannot create a subscription!");
            }
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
        .client()
        .unwrap();

    ws::start(
        r,
        OPCUASession {
            hb: Instant::now(),
            client,
            session: None,
            rt: r.state().runtime.clone(),
        },
    )
}

#[derive(Clone)]
struct HttpServerState {
    runtime: Arc<Runtime>,
}

fn run_server(address: String, rt: Arc<Runtime>) {
    HttpServer::new(move || {
        let base_path = "./html";
        let state = HttpServerState {
            runtime: rt.clone(),
        };
        App::with_state(state)
            // Websocket
            .resource("/ws/", |r| r.method(http::Method::GET).f(ws_create_request))
            // Static content
            .handler(
                "/",
                fs::StaticFiles::new(base_path)
                    .unwrap()
                    .index_file("index.html"),
            )
    })
    .bind(address)
    .unwrap()
    .run();
}
