use std::{
    error::Error,
    net::SocketAddr,
    {env, io},
};
use tokio::net::UdpSocket;

use opcua::pubsub::mqtt::Transport;
use opcua::pubsub::{
    core::writer_group::WriterGroup,
    mqtt::{MQTTConfig, MQTT_DEFAULT_PORT},
    publisher::{Publisher, PublisherBuilder},
};
use opcua::types::BrokerTransportQualityOfService;

struct Server {
    socket: UdpSocket,
    buf: Vec<u8>,
    to_send: Option<(usize, SocketAddr)>,
    publisher: Box<Publisher>,
}

impl Server {
    async fn run(self) -> Result<(), io::Error> {
        let Server {
            socket,
            mut buf,
            mut to_send,
            mut publisher,
        } = self;

        loop {
            // TODO replace with pubsub

            // ----> REMOVE

            // First we check to see if there's a message we need to echo back.
            // If so then we try to send it back to the original source, waiting
            // until it's writable and we're able to do so.
            if let Some((size, peer)) = to_send {
                let amt = socket.send_to(&buf[..size], &peer).await?;

                println!("Echoed {}/{} bytes to {}", amt, size, peer);
            }

            // If we're here then `to_send` is `None`, so we take a look for the
            // next message we're going to echo back.
            to_send = Some(socket.recv_from(&mut buf).await?);

            // <---- REMOVE
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let addr = env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:8080".to_string());

    let mqtt = MQTTConfig::new(
        Transport::Tls,
        "mqtt_server",
        MQTT_DEFAULT_PORT,
        "/",
        BrokerTransportQualityOfService::BestEffort,
    );

    // TODO set up writer group
    let writer_group = WriterGroup::default();

    // Create a publisher
    let publisher = PublisherBuilder::new()
        .mqtt(mqtt)
        .add_writer_group(writer_group)
        .build();

    let socket = UdpSocket::bind(&addr).await?;
    println!("Listening on: {}", socket.local_addr()?);

    let server = Server {
        socket,
        buf: vec![0; 1024],
        to_send: None,
        publisher: Box::new(publisher),
    };

    // This starts the server task.
    server.run().await?;

    Ok(())
}
