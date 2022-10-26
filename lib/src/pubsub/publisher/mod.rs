use std::sync::Arc;

use crate::types::*;

use crate::pubsub::core::*;

#[cfg(feature = "pubsub-mqtt")]
use crate::pubsub::mqtt::*;

pub trait Publisher {
    fn publish(&self /* dataset */);
}

struct NullPublisher {}

impl Publisher for NullPublisher {
    fn publish(&self) {
        todo!()
    }
}

pub enum MessageMapping {
    JSON,
    UADP,
}

pub enum Config {
    Empty,
    #[cfg(feature = "pubsub-mqtt")]
    MQTT(MQTTConfig),
    // UDP
}

pub struct PublisherBuilder {
    message_mapping: MessageMapping,
    config: Config,
    writer_groups: Vec<WriterGroup>,
}

impl PublisherBuilder {
    pub fn new() -> Self {
        Self {
            message_mapping: MessageMapping::UADP,
            config: Config::Empty,
            writer_groups: Vec::new(),
        }
    }

    pub fn uadp(mut self) -> Self {
        self.message_mapping = MessageMapping::UADP;
        self
    }

    pub fn json(mut self) -> Self {
        self.message_mapping = MessageMapping::JSON;
        self
    }

    #[cfg(feature = "pubsub-mqtt")]
    pub fn mqtt(mut self, config: MQTTConfig) -> Self {
        self.config = Config::MQTT(config);
        self
    }

    pub fn add_writer_group(mut self, writer_group: WriterGroup) -> Self {
        self.writer_groups.push(writer_group);
        self
    }

    pub fn build(self) -> Box<dyn Publisher> {
        match self.message_mapping {
            MessageMapping::JSON => {
                println!("JSON writer should be created")
            }
            MessageMapping::UADP => {
                println!("UADP writer should be created")
            }
        }
        match self.config {
            Config::Empty => {
                panic!("Can't create a publisher, type has not been set")
            }
            #[cfg(feature = "pubsub-mqtt")]
            Config::MQTT(_) => {
                println!("Create an MQTT publisher")
            }
        }
        Box::new(NullPublisher {})
    }
}
