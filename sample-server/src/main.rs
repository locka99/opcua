extern crate opcua_core;
extern crate opcua_server;

fn main() {
    use opcua_server::{Server};
    let _ = opcua_core::init_logging();
    let mut server = Server::new_default();
    server.run();
}
