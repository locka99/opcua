extern crate clap;
extern crate nannou;
extern crate opcua_client;
extern crate opcua_core;
extern crate opcua_types;

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};
use std::thread;
use std::path::PathBuf;

use clap::Arg;
use nannou::prelude::*;
use nannou::ui::prelude::*;

use opcua_client::prelude::*;
use opcua_types::*;


struct State {
    pub connected: bool,
    pub values: BTreeMap<String, DataValue>,
}

impl State {
    pub fn new() -> State {
        State {
            connected: true,
            values: BTreeMap::new(),
        }
    }
}

struct Model {
    ui: Ui,
    state: Arc<RwLock<State>>,
}

fn main() {
    // Read command line arguments
    let (config_file, endpoint_id) = {
        let m = clap::App::new("Simple OPC UA Client")
            .arg(Arg::with_name("config")
                .long("config")
                .help("Sets the configuration file to read settings and endpoints from")
                .takes_value(true)
                .default_value("../client.conf")
                .required(false))
            .arg(Arg::with_name("id")
                .long("endpoint-id")
                .help("Sets the endpoint id from the config file to connect to")
                .takes_value(true)
                .default_value("")
                .required(false))
            .get_matches();
        (m.value_of("config").unwrap().to_string(), m.value_of("id").unwrap().to_string())
    };

    // Optional - enable OPC UA logging
    opcua_core::init_logging();

    // Use the sample client config to set up a client. The sample config has a number of named
    // endpoints one of which is marked as the default.
    let mut client = Client::new(ClientConfig::load(&PathBuf::from(config_file)).unwrap());
    let endpoint_id = if !endpoint_id.is_empty() { Some(endpoint_id) } else { None };
    if let Ok(session) = client.connect_and_activate(endpoint_id) {
        // Spawn a thread for the OPC UA client
        thread::spawn(move || {
            // The --subscribe arg decides if code should subscribe to values, or just fetch those
            // values and exit
            let result = subscription_loop(session);
            if let Err(result) = result {
                println!("ERROR: Got an error while performing action - {:?}", result.description());
            }
        });

        // Now the UI thread
        start_ui();
    }
}

fn nodes_to_monitor() -> Vec<ReadValueId> {
    vec![
        ReadValueId::from(NodeId::from((2, "v1"))),
        ReadValueId::from(NodeId::from((2, "v2"))),
        ReadValueId::from(NodeId::from((2, "v3"))),
        ReadValueId::from(NodeId::from((2, "v4"))),
    ]
}

fn print_value(read_value_id: &ReadValueId, data_value: &DataValue) {
    let node_id = read_value_id.node_id.to_string();
    if let Some(ref value) = data_value.value {
        println!("Item \"{}\", Value = {:?}", node_id, value);
    } else {
        println!("Item \"{}\", Value not found, error: {}", node_id, data_value.status.as_ref().unwrap().description());
    }
}

fn subscription_loop(session: Arc<RwLock<Session>>) -> Result<(), StatusCode> {
    // Create a subscription
    println!("Creating subscription");

    // This scope is important - we don't want to session to be locked when the code hits the
    // loop below
    {
        let mut session = session.write().unwrap();

        // Creates our subscription - one update every 5 seconds
        let subscription_id = session.create_subscription(5f64, 10, 30, 0, 0, true, DataChangeCallback::new(|items| {
            println!("Data change from server:");
            items.iter().for_each(|item| {
                print_value(&item.item_to_monitor(), &item.value());
            });
        }))?;
        println!("Created a subscription with id = {}", subscription_id);

        // Create some monitored items
        let read_nodes = nodes_to_monitor();
        let items_to_create: Vec<MonitoredItemCreateRequest> = read_nodes.into_iter().map(|read_node| {
            MonitoredItemCreateRequest::new(read_node, MonitoringMode::Reporting, MonitoringParameters::default())
        }).collect();
        let _ = session.create_monitored_items(subscription_id, items_to_create)?;
    }

    // Loops forever. The publish thread will call the callback with changes on the variables
    loop {
        {
            // Break the loop if connection goes down
            let session = session.read().unwrap();
            if !session.is_connected() {
                println!("Connection to server broke, so terminating");
                break;
            }
        }

        // Main thread has nothing to do - just wait for publish events to roll in
        use std::thread;
        use std::time;
        thread::sleep(time::Duration::from_millis(1000));
    }

    Ok(())
}

fn start_ui() {
    // We'll kick off the OPC UA client on one thread and the UI on another
    // The UI will operate off a Model object which stores OPC UA data values
    // that we subscribe for

    nannou::run(model, event, view);
}

fn model(app: &App) -> Model {
    app.set_loop_mode(LoopMode::wait(3));
    let mut ui = app.new_ui().build().unwrap();
    Model {
        state: Arc::new(RwLock::new(State::new())),
        ui
    }
}

fn event(app: &App, mut model: Model, event: Event) -> Model {
    if let Event::Update(_update) = event {
        // Update the model
        {
            let ui = &mut model.ui.set_widgets();
            /*
        fn number_tile(value: f64, (x, y): (f64, f64), (w, h): (f64, f64)) -> widget::Text {
            widget::Text::new(value.into())
                .w_h(w, h)
                .rgb(1.0, 1.0, 1.0)
                .border(0.0)
        }
*/
            // number_tile(100.0).x
        }
        model
    } else {
        model
    }
}

fn view(app: &App, model: &Model, frame: Frame) -> Frame {
    let draw = app.draw();

    draw.background().rgb(0.02, 0.02, 0.02);
    draw.to_frame(app, &frame).unwrap();

    // Draw the values
    // Iterate the state and for each datavalue
    {
        let state = model.state.as_ref().read().unwrap();

        let mut row = 0;
        let mut col = 0;

        const TILE_WIDTH: u32 = 200;
        const TILE_HEIGHT: u32 = 200;
        const PADDING: u32 = 20;

        for v in &state.values {
            let (node_id, value) = v;

            if !value.is_valid() {
                // Set text colour to red
            } else {
                // Set text colour to white
            }

            // Turn the value into a string to render it
            let (x, y) = (col * (TILE_WIDTH + PADDING), row * (TILE_HEIGHT + PADDING));


            // Go to the next "tile"
            let col = if col == 3 {
                row += 1;
                0
            } else {
                col + 1
            };
        }
    }

    frame
}