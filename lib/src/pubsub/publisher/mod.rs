use crate::types::*;

use crate::pubsub::core::DataSet;

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

pub struct MQTTConfig {}

pub enum Config {
    Empty,
    MQTT(MQTTConfig),
    // UDP
}

pub struct PublisherBuilder {
    message_mapping: MessageMapping,
    config: Config,
}

impl PublisherBuilder {
    pub fn new() -> Self {
        Self {
            message_mapping: MessageMapping::UADP,
            config: Config::Empty,
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

    pub fn mqtt(mut self, config: MQTTConfig) -> Self {
        self.config = Config::MQTT(config);
        self
    }

    pub fn build(self) -> Box<Publisher> {
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
            Config::MQTT(_) => {
                println!("Create an MQTT publisher")
            }
        }
        Box::new(NullPublisher {})
    }
}
