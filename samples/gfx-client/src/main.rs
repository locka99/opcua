//! This is a simple client with a graphical front end that monitors and displays values from
//! a server. The files are read from a monitored_items.txt which should be in the working
//! directory that the program is run from.

extern crate clap;
extern crate conrod;
extern crate opcua_client;
extern crate opcua_core;
extern crate opcua_types;
extern crate opcua_console_logging;

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};
use std::thread;
use std::path::PathBuf;

use clap::Arg;

use conrod::{widget, Colorable, Positionable, Sizeable, Widget, Ui};
use conrod::backend::glium::glium::{self, Surface};

use opcua_client::prelude::*;

struct ConnectionState {
    pub connected: bool,
    pub values: BTreeMap<String, DataValue>,
}

impl ConnectionState {
    pub fn new() -> ConnectionState {
        ConnectionState {
            connected: true,
            values: BTreeMap::new(),
        }
    }
}

struct UiModel {
    ids: BTreeMap<String, widget::Id>,
    state: Arc<RwLock<ConnectionState>>,
}

const ERROR_ID: &'static str = "###ERROR###";
const WIDTH: u32 = 640;
const HEIGHT: u32 = 480;

impl UiModel {
    pub fn ensure_ids(&mut self, ui: &mut Ui) {
        let mut id_generator = ui.widget_id_generator();
        self.ids.insert(String::from(ERROR_ID), id_generator.next());
        let mut names = {
            let state = self.state.read().unwrap();
            state.values.keys().map(|k| k.clone()).collect::<Vec<String>>()
        };
        names.drain(..).for_each(|name| {
            if !self.ids.contains_key(&name) {
                self.ids.insert(name, id_generator.next());
            }
        });
    }

    pub fn id_for(&self, name: &str) -> Option<widget::Id> {
        if let Some(id) = self.ids.get(name) {
            Some(*id)
        } else {
            None
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


    if let Ok(session) = client.connect_and_activate(endpoint_id) {
        // Create a shared state object
        let state = Arc::new(RwLock::new(ConnectionState::new()));

        // Construct the UI and ids
        let mut ui = conrod::UiBuilder::new([WIDTH as f64, HEIGHT as f64]).build();
        let mut model = UiModel {
            state: state.clone(),
            ids: BTreeMap::new(),
        };

        {
            // Spawn a thread for the OPC UA client
            let state = state.clone();
            thread::spawn(move || {
                // The --subscribe arg decides if code should subscribe to values, or just fetch those
                // values and exit
                let result = subscription_loop(session, state);
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

fn subscription_loop(session: Arc<RwLock<Session>>, state: Arc<RwLock<ConnectionState>>) -> Result<(), StatusCode> {
    // Create a subscription

    // This scope is important - we don't want to session to be locked when the code hits the
    // loop below
    {
        let mut session = session.write().unwrap();

        // Creates our subscription - one update every 2 seconds
        let subscription_id = session.create_subscription(2000.0, 10, 30, 0, 0, true, move |items| {
            let mut state = state.write().unwrap();
            items.iter().for_each(|item| {
                // Each value will be applied to the state so that the UI thread can update it
                let key = item.item_to_monitor().node_id.to_string();
                state.values.insert(key, item.value().clone());
            });
        })?;
        println!("Created a subscription with id = {}", subscription_id);

        // Create some monitored items
        let read_nodes = nodes_to_monitor();
        let items_to_create: Vec<MonitoredItemCreateRequest> = {
            read_nodes.into_iter().map(move |read_node| {
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
        .with_dimensions(WIDTH, HEIGHT);
    let context = glium::glutin::ContextBuilder::new()
        .with_vsync(true)
        .with_multisampling(4);
    let display = glium::Display::new(window, context, &events_loop).unwrap();

    // Add a `Font` to the `Ui`'s `font::Map` from file.
    const FONT_PATH: &'static str = "./assets/fonts/NotoSans/NotoSans-Regular.ttf";
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

        // Process the events.
        for event in events.drain(..) {
            // Break from the loop upon `Escape` or closed window.
            match event.clone() {
                glium::glutin::Event::WindowEvent { event, .. } => {
                    match event {
                        glium::glutin::WindowEvent::Closed |
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
        draw_cells(&mut ui, &mut model);

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

const BAD_COLOUR: (f32, f32, f32) = (1.0, 0.0, 0.0);
const GOOD_COLOUR: (f32, f32, f32) = (1.0, 1.0, 1.0);

fn draw_cells(ui: &mut Ui, model: &mut UiModel) {
    fn number_cell<'a>(value: &'a str, valid: bool, x: f64, y: f64, w: f64, h: f64) -> widget::Text<'a> {
        let (r, g, b) = if valid { GOOD_COLOUR } else { BAD_COLOUR };
        widget::Text::new(value)
            .w_h(w, h)
            .x_y(x, y)
            .center_justify()
            .rgb(r, g, b)
    }

    model.ensure_ids(ui);

    let ui = &mut ui.set_widgets();

    const CELL_WIDTH: f64 = 100.;
    const CELL_HEIGHT: f64 = 100.;
    const PADDING: f64 = 10.;


    // Create text widgets for each value
    {
        let state = model.state.read().unwrap();

        // Create / update the widgets
        if state.values.is_empty() {
            // For some reason there are no values, so put up an error box to signify an error
            if let Some(error_id) = model.id_for(&String::from(ERROR_ID)) {
                widget::Text::new("Waiting for values, check console output with RUST_OPCUA_LOG=debug")
                    .align_middle_x()
                    .align_middle_y()
                    .center_justify()
                    .rgb(BAD_COLOUR.0, BAD_COLOUR.1, BAD_COLOUR.2).set(error_id, ui)
            }
        } else {
            let num_cols: usize = 2;
            let start_x = (ui.win_w - (num_cols as f64 * (CELL_WIDTH + PADDING))) / 2.0;
            let start_y = 0.0;
            state.values.iter().enumerate().for_each(|(i, v)| {
                // Create / update the cell and its state
                let (node_id, value) = v;
                if let Some(id) = model.ids.get(node_id) {
                    let valid = value.is_valid();
                    let value = if let Some(ref value) = value.value {
                        value.to_string()
                    } else {
                        "None".to_string()
                    };
                    // Turn the value into a string to render it
                    let (col, row) = (i % num_cols, i / num_cols);
                    let (x, y) = (start_x + (col as f64 * (CELL_WIDTH + PADDING)), start_y + row as f64 * (CELL_HEIGHT + PADDING));
                    number_cell(&value, valid, x, y, CELL_WIDTH, CELL_HEIGHT).set(*id, ui);
                } else {
                    println!("No id called {}", node_id);
                }
            });
        }
    }
}
