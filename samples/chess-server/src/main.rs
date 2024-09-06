// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

use std::env;
use std::sync::Arc;
use std::time::Duration;

use opcua::server::address_space::VariableBuilder;
use opcua::server::node_manager::memory::{
    simple_node_manager, NamespaceMetadata, SimpleNodeManager,
};
use opcua::server::{ServerBuilder, SubscriptionCache};
use opcua::sync::Mutex;
use opcua::types::*;

mod game;

// These are squares on the board which will become variables with the same
// name
const BOARD_SQUARES: [&'static str; 64] = [
    "a8", "b8", "c8", "d8", "e8", "f8", "g8", "h8", "a7", "b7", "c7", "d7", "e7", "f7", "g7", "h7",
    "a6", "b6", "c6", "d6", "e6", "f6", "g6", "h6", "a5", "b5", "c5", "d5", "e5", "f5", "g5", "h5",
    "a4", "b4", "c4", "d4", "e4", "f4", "g4", "h4", "a3", "b3", "c3", "d3", "e3", "f3", "g3", "h3",
    "a2", "b2", "c2", "d2", "e2", "f2", "g2", "h2", "a1", "b1", "c1", "d1", "e1", "f1", "g1", "h1",
];

fn default_engine_path() -> String {
    // This is the default chess engine that will be launched absent of one being passed on the
    // command line.
    String::from(if cfg!(windows) {
        "stockfish_9_x32.exe"
    } else {
        "stockfish"
    })
}

#[tokio::main]
async fn main() {
    let engine_path = if env::args().len() > 1 {
        env::args().nth(1).unwrap()
    } else {
        default_engine_path()
    };
    println!("Launching chess engine \"{}\"", engine_path);
    let game = Arc::new(Mutex::new(game::Game::new(&engine_path)));

    // Create an OPC UA server with sample configuration and default node set
    let (server, handle) = ServerBuilder::new()
        .with_config_from("../server.conf")
        .with_node_manager(simple_node_manager(
            NamespaceMetadata {
                namespace_uri: "urn:chess-server".to_owned(),
                ..Default::default()
            },
            "chess",
        ))
        .build()
        .unwrap();
    let node_manager = handle
        .node_managers()
        .get_of_type::<SimpleNodeManager>()
        .unwrap();
    let ns = handle.get_namespace_index("urn:chess-server").unwrap();

    {
        let mut address_space = node_manager.address_space().write();

        let board_node_id = NodeId::new(2, "board");
        address_space.add_folder(
            &board_node_id,
            "Board",
            "Board",
            &NodeId::objects_folder_id(),
        );

        BOARD_SQUARES.iter().for_each(|square| {
            // Variable represents each square's state
            let browse_name = *square;
            let node_id = NodeId::new(ns, *square);
            VariableBuilder::new(&node_id, browse_name, browse_name)
                .organized_by(&board_node_id)
                .data_type(DataTypeId::Byte)
                .value(0u8)
                .insert(&mut address_space);

            // Another variable is a highlighting flag for the square
            let browse_name = format!("{}.highlight", square);
            let node_id = NodeId::new(ns, browse_name.clone());
            VariableBuilder::new(&node_id, browse_name, "")
                .organized_by(&board_node_id)
                .data_type(DataTypeId::Boolean)
                .value(false)
                .insert(&mut address_space);
        });
    };

    {
        let game = game.lock();
        update_board_state(&game, &node_manager, 2, &handle.subscriptions());
    }

    // Spawn a thread for the game which will update server state

    // Each variable will hold a value representing what's in the square. A client can subscribe to the content
    // of the variables and observe games being played.

    tokio::task::spawn(async move {
        let sleep_time = Duration::from_millis(1500);
        let mut game = game.lock();
        loop {
            game.set_position();
            let bestmove = game.bestmove().unwrap();

            // uci is a wonderfully terrible specification as evidenced by the way various chess engines
            // return no-bestmove answers
            let end_game = bestmove == "(none)"
                || bestmove == "a1a1"
                || bestmove == "NULL"
                || bestmove == "0000";
            if end_game || game.half_move_clock >= 50 {
                println!(
                    "Resetting the game - best move = {}, half move clock = {}",
                    bestmove, game.half_move_clock
                );
                // Reset the board
                game.reset();
            } else {
                println!("best move = {}", bestmove);
                game.make_move(bestmove);
                game.print_board();

                update_board_state(&game, &node_manager, ns, &handle.subscriptions());
            }

            tokio::time::sleep(sleep_time).await;
        }
    });

    // Run the server.
    server.run().await.unwrap();
}

fn update_board_state(
    game: &game::Game,
    nm: &SimpleNodeManager,
    ns: u16,
    subscriptions: &SubscriptionCache,
) {
    let now = DateTime::now();
    BOARD_SQUARES.iter().for_each(|square| {
        // Piece on the square
        let square_value = game.square_from_str(square);
        let node_id = NodeId::new(ns, *square);

        nm.set_value(
            subscriptions,
            &node_id,
            None,
            DataValue::new_at(square_value as u8, now),
        )
        .unwrap();

        // Highlight the square
        let node_id = NodeId::new(ns, format!("{}.highlight", square));
        let highlight_square = if let Some(ref last_move) = game.last_move {
            last_move.contains(square)
        } else {
            false
        };
        nm.set_value(
            subscriptions,
            &node_id,
            None,
            DataValue::new_at(highlight_square, now),
        )
        .unwrap();
    });
}
