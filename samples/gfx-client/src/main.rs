//! This is a graphical client that monitors and displays values from
//! a server. The files are read from a monitored_items.txt which should be in the working
//! directory that the program is run from.
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufReader, BufRead};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use std::thread;

use clap::Arg;

use conrod::{widget, Colorable, Positionable, Sizeable, Widget, Ui, widget_ids};
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
        message,
        grid
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
    let nodes_to_monitor = {
        let f = File::open("./monitored_items.txt").unwrap();
        BufReader::new(f).lines()
            .map(|line| line.unwrap())
            .filter(|line| line.len() > 0)
            .map(|line| ReadValueId::from(NodeId::from_str(&line).unwrap()))
            .collect::<Vec<_>>()
    };

    if let Ok(session) = client.connect_to_endpoint_id(endpoint_id) {
        // Create a shared state object
        let session_state = Arc::new(RwLock::new(SessionState::new()));

        // Construct the UI and ids
        let mut ui = conrod::UiBuilder::new([DISPLAY_WIDTH as f64, DISPLAY_HEIGHT as f64]).build();
        let model = UiModel::new(&mut ui, &nodes_to_monitor, session_state.clone());

        {
            // Spawn a thread for the OPC UA client
            let session_state = session_state.clone();
            thread::spawn(move || {
                let result = subscription_loop(nodes_to_monitor, session, session_state);
                if let Err(result) = result {
                    println!("ERROR: Got an error while performing action - {}", result);
                }
            });
        }

        // Now start the blocking UI
        start_ui(ui, model);
    }
}

fn subscription_loop(nodes_to_monitor: Vec<ReadValueId>, session: Arc<RwLock<Session>>, state: Arc<RwLock<SessionState>>) -> Result<(), StatusCode> {
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
        let result = session.create_monitored_items(subscription_id, TimestampsToReturn::Both, &items_to_create)?;
        println!("Created monitored items {:?}", result);
    }

    // Loops forever. The publish thread will call the callback with changes on the variables
    Session::run(session);

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

            // This is a hack to throttle the render loop so it doesn't spin around eating CPU
            thread::sleep(Duration::from_millis(100));
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
        // Turn the references in the map into a vector
        let values = state.values.iter().map(|(k, v)| (k, v)).collect::<Vec<_>>();

        let num_values = values.len();
        let num_cols: usize = 2;
        let num_rows = if num_values % num_cols == 0 { num_values / num_cols } else { (num_values / num_cols) + 1 };

        // Create a matrix to render the text in its cells
        let mut elements = widget::Matrix::new(num_cols, num_rows)
            .middle_of(ui.window)
            .cell_padding(PADDING, PADDING)
            .w((num_cols as f64 * (CELL_WIDTH + PADDING)) - PADDING)
            .h((num_rows as f64 * (CELL_HEIGHT + PADDING)) - PADDING)
            .set(model.static_ids.grid, ui);

        // Iterate the elements of the matrix, and render the values as text
        while let Some(elem) = elements.next(ui) {
            let idx = elem.row * num_cols + elem.col;
            if idx >= values.len() {
                break;
            }
            let v = values[idx];
            let (node_id, value) = v;
            if model.value_ids.contains_key(node_id) {
                let valid = value.is_valid();
                let value = if let Some(ref value) = value.value {
                    format!("{}\n[{}]", value.to_string(), node_id)
                } else {
                    "None".to_string()
                };
                let widget = widget::Text::new(&value)
                    .w_h(CELL_WIDTH, CELL_HEIGHT)
                    .center_justify()
                    .color(if valid { GOOD_COLOUR } else { BAD_COLOUR });
                elem.set(widget, ui);
            } else {
                panic!("No id called {}", node_id);
            }
        }
    }
}
