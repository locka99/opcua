//! This is a simple client with a graphical front end that monitors and displays values from
//! a server. The files are read from a monitored_items.txt which should be in the working
//! directory that the program is run from.

extern crate clap;
#[macro_use]
extern crate conrod;
extern crate opcua_client;


extern crate opcua_console_logging;

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};
use std::thread;
use std::path::PathBuf;

use clap::Arg;

use conrod::{widget, Colorable, Positionable, Sizeable, Widget, Ui};
use conrod::color;
use conrod::backend::glium::glium::{self, Surface};

use opcua_client::prelude::*;

// Screen styling

const DISPLAY_WIDTH: u32 = 640;
const DISPLAY_HEIGHT: u32 = 480;
const BACKGROUND_COLOUR: color::Color = color::BLACK;
const MESSAGE_COLOUR: color::Color = color::YELLOW;
const BAD_COLOUR: color::Color = color::RED;
const GOOD_COLOUR: color::Color = color::WHITE;
const CELL_WIDTH: f64 = 200.;
const CELL_HEIGHT: f64 = 80.;
const PADDING: f64 = 5.;

struct SessionState {
    pub connected: bool,
    /// Values of monitored items
    pub values: BTreeMap<String, DataValue>,
}

impl SessionState {
    pub fn new() -> SessionState {
        SessionState {
            connected: true,
            values: BTreeMap::new(),
        }
    }
}

widget_ids! {
    struct Ids {
        canvas,
        message
    }
}

struct UiModel {
    /// Static display elements
    static_ids: Ids,
    /// Value display elements
    value_ids: BTreeMap<String, widget::Id>,
    /// Session state, connection to OPC UA and current values of subscribed values
    session_state: Arc<RwLock<SessionState>>,
}

impl UiModel {
    /// Build the UI model, including creation of all the ids for widgets
    pub fn new(ui: &mut Ui, nodes_to_monitor: &Vec<ReadValueId>, session_state: Arc<RwLock<SessionState>>) -> UiModel {
        let mut id_generator = ui.widget_id_generator();
        let mut value_ids = BTreeMap::new();
        nodes_to_monitor.iter().for_each(|n| {
            let node_id = n.node_id.to_string();
            value_ids.insert(node_id, id_generator.next());
        });
        UiModel {
            static_ids: Ids::new(id_generator),
            value_ids,
            session_state,
        }
    }
}

fn main() {
    // Read command line arguments
    let (config_file, endpoint_id) = {
        let m = clap::App::new("OPC UA Gfx Client")
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
    opcua_console_logging::init();

    // Use the sample client config to set up a client. The sample config has a number of named
    // endpoints one of which is marked as the default.
    let mut client = Client::new(ClientConfig::load(&PathBuf::from(config_file)).unwrap());
    let endpoint_id: Option<&str> = if !endpoint_id.is_empty() { Some(&endpoint_id) } else { None };

    // Read the nodes from a file
    let nodes_to_monitor = nodes_to_monitor();

    if let Ok(session) = client.connect_and_activate(endpoint_id) {
        // Create a shared state object
        let session_state = Arc::new(RwLock::new(SessionState::new()));

        // Construct the UI and ids
        let mut ui = conrod::UiBuilder::new([DISPLAY_WIDTH as f64, DISPLAY_HEIGHT as f64]).build();
        let mut model = UiModel::new(&mut ui, &nodes_to_monitor, session_state.clone());

        {
            // Spawn a thread for the OPC UA client
            let session_state = session_state.clone();
            thread::spawn(move || {
                // The --subscribe arg decides if code should subscribe to values, or just fetch those
                // values and exit
                let result = subscription_loop(nodes_to_monitor, session, session_state);
                if let Err(result) = result {
                    println!("ERROR: Got an error while performing action - {:?}", result.description());
                }
            });
        }

        // Now start the blocking UI
        start_ui(ui, model);
    }
}

fn nodes_to_monitor() -> Vec<ReadValueId> {
    use std::io::{BufReader, BufRead};
    use std::fs::File;
    use std::str::FromStr;
    if let Ok(f) = File::open("./monitored_items.txt") {
        let f = BufReader::new(f);
        let mut result = Vec::new();
        for line in f.lines().map(|l| l.unwrap()) {
            if line.len() > 0 {
                result.push(ReadValueId::from(NodeId::from_str(&line).unwrap()));
            }
        }
        result
    } else {
        panic!("Can't open monitored_items file")
    }
}

fn subscription_loop(nodes_to_monitor: Vec<ReadValueId>, session: Arc<RwLock<Session>>, state: Arc<RwLock<SessionState>>) -> Result<(), StatusCode> {
    // Create a subscription

    // This scope is important - we don't want to session to be locked when the code hits the
    // loop below
    {
        let mut session = session.write().unwrap();

        // Creates our subscription - one update every 2 seconds
        let subscription_id = session.create_subscription(2000.0, 10, 30, 0, 0, true, DataChangeCallback::new(move |items| {
            let mut state = state.write().unwrap();
            items.iter().for_each(|item| {
                // Each value will be applied to the state so that the UI thread can update it
                let key = item.item_to_monitor().node_id.to_string();
                state.values.insert(key, item.value().clone());
            });
        }))?;
        println!("Created a subscription with id = {}", subscription_id);

        // Create some monitored items
        let items_to_create: Vec<MonitoredItemCreateRequest> = {
            nodes_to_monitor.into_iter().map(move |read_node| {
                println!("Monitoring item {:?}", read_node);
                MonitoredItemCreateRequest::new(read_node, MonitoringMode::Reporting, MonitoringParameters::default())
            }).collect()
        };
        let result = session.create_monitored_items(subscription_id, &items_to_create)?;
        println!("Created monitored items {:?}", result);
    }

    // Loops forever. The publish thread will call the callback with changes on the variables
    loop {
        {
            // Break the loop if connection goes down
            let mut session = session.write().unwrap();
            if !session.is_connected() {
                println!("Connection to server broke, so terminating");
                break;
            }
            // Main thread has nothing to do - just wait for publish events to roll in
            session.poll();
        }
    }

    Ok(())
}

fn start_ui(mut ui: Ui, mut model: UiModel) {
    // Build the window.
    let mut events_loop = glium::glutin::EventsLoop::new();
    let window = glium::glutin::WindowBuilder::new()
        .with_title("Visualizer OPC UA Client")
        .with_dimensions((DISPLAY_WIDTH, DISPLAY_HEIGHT).into());
    let context = glium::glutin::ContextBuilder::new()
        .with_vsync(true)
        .with_multisampling(4);
    let display = glium::Display::new(window, context, &events_loop).unwrap();

    // Add a `Font` to the `Ui`'s `font::Map` from file.
    const FONT_PATH: &str = "./assets/fonts/NotoSans/NotoSans-Regular.ttf";
    ui.fonts.insert_from_file(FONT_PATH).unwrap();

    // A type used for converting `conrod::render::Primitives` into `Command`s that can be used
    // for drawing to the glium `Surface`.
    let mut renderer = conrod::backend::glium::Renderer::new(&display).unwrap();

    // The image map describing each of our widget->image mappings (in our case, none).
    let image_map = conrod::image::Map::<glium::texture::Texture2d>::new();

    let mut events = Vec::new();

    'render: loop {
        // Get all the new events since the last frame.
        events_loop.poll_events(|event| { events.push(event); });

        // If there are no new events, wait for one.
        if events.is_empty() {
            // This code is commented out because I don't know how to post a custom event that
            // could break the loop when an OPC UA subscription change is received. It would be far
            // more efficient to do that than spinning around the the 'render loop continuously.

//            events_loop.run_forever(|event| {
//                events.push(event);
//                glium::glutin::ControlFlow::Break
//            });

        }

        // Process the events.
        for event in events.drain(..) {
            // Break from the loop upon `Escape` or closed window.
            match event.clone() {
                glium::glutin::Event::WindowEvent { event, .. } => {
                    match event {
                        glium::glutin::WindowEvent::CloseRequested |
                        glium::glutin::WindowEvent::KeyboardInput {
                            input: glium::glutin::KeyboardInput {
                                virtual_keycode: Some(glium::glutin::VirtualKeyCode::Escape),
                                ..
                            },
                            ..
                        } => break 'render,
                        _ => (),
                    }
                }
                _ => (),
            };

            // Use the `winit` backend feature to convert the winit event to a conrod input.
            let input = match conrod::backend::winit::convert_event(event, &display) {
                None => continue,
                Some(input) => input,
            };

            // Handle the input with the `Ui`.
            ui.handle_event(input);
        }

        // Set the widgets.
        draw_ui(&mut ui, &mut model);

        // Draw the `Ui` if it has changed.
        if let Some(primitives) = ui.draw_if_changed() {
            renderer.fill(&display, primitives, &image_map);
            let mut target = display.draw();
            target.clear_color(0.0, 0.0, 0.0, 1.0);
            renderer.draw(&display, &mut target, &image_map).unwrap();
            target.finish().unwrap();
        }
    }
}

fn draw_ui(ui: &mut Ui, model: &mut UiModel) {
    let ui = &mut ui.set_widgets();

    // Canvas is the backdrop to the view
    widget::Canvas::new()
        .color(BACKGROUND_COLOUR)
        .set(model.static_ids.canvas, ui);

    // Create text widgets for each value
    let state = model.session_state.read().unwrap();

    // Create / update the widgets
    if state.values.is_empty() {
        // For some reason there are no values, so put up an error box to signify an error
        widget::Text::new("Waiting for values, check console output with RUST_OPCUA_LOG=debug")
            .middle_of(ui.window)
            .center_justify()
            .color(MESSAGE_COLOUR)
            .set(model.static_ids.message, ui)
    } else {
        let num_cols: usize = 2;

        let start_x = 0.0;
        let start_y = 0.0;

        state.values.iter().enumerate().for_each(|(i, v)| {
            // Create / update the cell and its state
            let (node_id, value) = v;
            if let Some(id) = model.value_ids.get(node_id) {
                let (col, row) = (i % num_cols, i / num_cols);
                let valid = value.is_valid();
                let value = if let Some(ref value) = value.value {
                    format!("{} ({}) ({}, {})", value.to_string(), node_id, col, row)
                } else {
                    "None".to_string()
                };
                // Turn the value into a string to render it
                let (x, y) = (start_x + (col as f64 * (CELL_WIDTH + PADDING)), start_y + row as f64 * (CELL_HEIGHT + PADDING));
                // println!("col = {}, row = {}, x = {}, y = {}", col, row, x, y);
                value_widget(&value, valid, x, y, CELL_WIDTH, CELL_HEIGHT, model.static_ids.canvas)
                    .set(*id, ui);
            } else {
                panic!("No id called {}", node_id);
            }
        });
    }
}

fn value_widget(value: &str, valid: bool, x: f64, y: f64, w: f64, h: f64, _canvas_id: conrod::widget::Id) -> widget::Text<'_> {
    let color = if valid { GOOD_COLOUR } else { BAD_COLOUR };
    widget::Text::new(value)
        .x_y(x, y)
        .w(w).h(h)
        .center_justify()
        .color(color)
}