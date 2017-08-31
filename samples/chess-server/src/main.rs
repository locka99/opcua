extern crate uci;
extern crate opcua_server;

use std::env;
use std::sync::{Arc, Mutex};
use std::thread;

use opcua_server::prelude::*;

mod game;

// These are squares on the board which will become variables with the same
// name
const BOARD_SQUARES: [&'static str; 64] = [
    "a8", "b8", "c8", "d8", "e8", "f8", "g8", "h8",
    "a7", "b7", "c7", "d7", "e7", "f7", "g7", "h7",
    "a6", "b6", "c6", "d6", "e6", "f6", "g6", "h6",
    "a5", "b5", "c5", "d5", "e5", "f5", "g5", "h5",
    "a4", "b4", "c4", "d4", "e4", "f4", "g4", "h4",
    "a3", "b3", "c3", "d3", "e3", "f3", "g3", "h3",
    "a2", "b2", "c2", "d2", "e2", "f2", "g2", "h2",
    "a1", "b1", "c1", "d1", "e1", "f1", "g1", "h1",
];

#[cfg(any(not(windows)))]
fn default_engine_path() -> String{
    String::from("stockfish")
}

#[cfg(any(windows))]
fn default_engine_path() -> String{
    String::from("stockfish_8_x32.exe")
}

fn main() {

    let engine_path = if env::args().len() > 1 {
        env::args().nth(1).unwrap()
    } else {
        default_engine_path()
    };
    println!("Launching chess engine \"{}\"", engine_path);
    let game = Arc::new(Mutex::new(game::Game::new(&engine_path)));

    // Create an OPC UA server with sample configuration and default node set
    let mut server = Server::new(ServerConfig::default_sample());

    {
        let server_state = server.server_state.lock().unwrap();
        let mut address_space = server_state.address_space.lock().unwrap();
        let board_node_id = address_space
            .add_folder("Board", "Board", &AddressSpace::objects_folder_id())
            .unwrap();

        for square in BOARD_SQUARES.iter() {
            let node_id = NodeId::new_string(2, square);
            let _ = address_space.add_variable(Variable::new_byte(&node_id, square, square, "", 0), &board_node_id);
        }

        let game = game.lock().unwrap();
        update_board_state(&game, &mut address_space);
    }

    // Spawn a thread for the game which will update server state

    // Each variable will hold a value representing what's in the square. A client can subscribe to the content
    // of the variables and observe games being played.
    let server_state = server.server_state.clone();

    thread::spawn(move || {
        let mut game = game.lock().unwrap();
        loop {
            game.set_position();
            let bestmove = game.bestmove().unwrap();
            if bestmove == "(none)" || game.half_move_clock > 50 {
                println!("Resetting the game - best move = {}, half move clock = {}", bestmove, game.half_move_clock);
                // Reset the board
                game.reset();
            } else {
                println!("best move = {}", bestmove);
                game.make_move(bestmove);
                game.print_board();
                {
                    let server_state = server_state.lock().unwrap();
                    let mut address_space = server_state.address_space.lock().unwrap();
                    update_board_state(&game, &mut address_space);
                }
            }
        }
    });

    // Run the server. This does not ordinarily exit so you must Ctrl+C to terminate
    server.run();
}

fn update_board_state(game: &game::Game, address_space: &mut AddressSpace) {
    for square in BOARD_SQUARES.iter() {
        let square_value = game.square_from_str(square);
        let node_id = NodeId::new_string(2, square);
        let _ = address_space.set_value_by_node_id(&node_id, Variant::Byte(square_value as u8));
    }
}
