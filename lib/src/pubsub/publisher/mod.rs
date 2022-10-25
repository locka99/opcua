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

pub const MQTT_DEFAULT_PORT: u16 = 8333;
pub const WSS_DEFAULT_PORT: u16 = 443;

pub struct MQTTConfig {
    domain: String,
    port: u16,
    path: String,
    qos: BrokerTransportQualityOfService,
}

impl MQTTConfig {
    pub fn new<S, T>(domain: S, port: u16, path: T) -> Self
    where
        S: Into<String>,
        T: Into<String>,
    {
        Self {
            domain: domain.into(),
            port,
            path: path.into(),
            qos: BrokerTransportQualityOfService::AtLeastOnce,
        }
    }

    pub fn as_url(&self) -> String {
        return format!("mqtt://{}:{}{}", self.domain, self.port, self.path);
    }
}

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

    pub fn add_published_dataset(mut self) -> Self {
        self
    }

    pub fn add_writer_group(mut self) -> Self {
        self
    }

    pub fn add_dataset_writer(mut self) -> Self {
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
            Config::MQTT(_) => {
                println!("Create an MQTT publisher")
            }
        }
        Box::new(NullPublisher {})
    }
}
