// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

use std::{
    error::Error,
    net::SocketAddr,
    sync::Arc,
    {env, io},
};
use tokio::net::UdpSocket;

use opcua::pubsub::{
    core::{DataSetWriter, WriterGroup},
    json::DataSetWriter as JsonDataSetWriter,
    publisher::{Publisher, PublisherBuilder},
    transport::mqtt::{MQTTConfig, MQTTProtocol, MQTT_DEFAULT_PORT},
};
use opcua::types::{
    BrokerTransportQualityOfService, DataSetFieldContentMask, JsonDataSetMessageContentMask,
};

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
            publisher,
        } = self;

        loop {
            // TODO replace with pubsub

            // Check for pending message

            // Push

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

    // This server is going to publish events to an MQTT server described below
    let mqtt_server = "localhost";
    let mqtt_port = MQTT_DEFAULT_PORT;
    let mqtt_path = "/";
    let mqtt_topic = "sample-opcua-topic";

    let mqtt = MQTTConfig::new(
        MQTTProtocol::Tls,
        mqtt_server,
        mqtt_port,
        mqtt_path,
        mqtt_topic,
        BrokerTransportQualityOfService::BestEffort,
    );

    // Writer group contains what will be written to MQTT
    let mut writer_group = WriterGroup::default();
    let message_content_mask = JsonDataSetMessageContentMask::DataSetWriterId
        | JsonDataSetMessageContentMask::SequenceNumber
        | JsonDataSetMessageContentMask::Status
        | JsonDataSetMessageContentMask::Timestamp;
    let field_content_mask = DataSetFieldContentMask::StatusCode;
    let writer: Arc<Box<dyn DataSetWriter>> = Arc::new(Box::new(JsonDataSetWriter::new(
        1,
        message_content_mask,
        field_content_mask,
    )));
    writer_group.add(writer);

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
