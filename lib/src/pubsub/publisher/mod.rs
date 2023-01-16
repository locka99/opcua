use crate::pubsub::core::writer_group::WriterGroup;

#[cfg(feature = "pubsub-mqtt")]
use crate::pubsub::mqtt::*;

// Publisher represents a connection that publishes data
pub struct Publisher {
    message_mapping: MessageMapping,
    connection_config: ConnectionConfig,
    writer_groups: Vec<WriterGroup>,
}

impl Publisher {
    pub fn publish(&self) {
        todo!()
    }
}

pub enum MessageMapping {
    /// Message is encoded as JSON
    JSON,
    /// Message is encoded with UA binary
    UADP,
}

pub enum ConnectionConfig {
    Empty,
    #[cfg(feature = "pubsub-mqtt")]
    MQTT(MQTTConfig),
    // UDP
}

pub struct PublisherBuilder {
    message_mapping: MessageMapping,
    connection_config: ConnectionConfig,
    writer_groups: Vec<WriterGroup>,
}

impl PublisherBuilder {
    pub fn new() -> Self {
        Self {
            message_mapping: MessageMapping::UADP,
            connection_config: ConnectionConfig::Empty,
            writer_groups: Vec::new(),
        }
    }

    #[cfg(feature = "pubsub-mqtt")]
    pub fn mqtt(mut self, config: MQTTConfig) -> Self {
        self.connection_config = ConnectionConfig::MQTT(config);
        self
    }

    pub fn server(mut self, url: &str) -> Self {
        #[cfg(feature = "pubsub-mqtt")]
        {
            if let Ok(config) = MQTTConfig::try_from(url) {
                self.connection_config = ConnectionConfig::MQTT(config);
                return self;
            }
        }
        panic!("Invalid / unsupported server url {}", url);
    }

    pub fn uadp(mut self) -> Self {
        self.message_mapping = MessageMapping::UADP;
        self
    }

    pub fn json(mut self) -> Self {
        self.message_mapping = MessageMapping::JSON;
        self
    }

    pub fn add_writer_group(mut self, writer_group: WriterGroup) -> Self {
        self.writer_groups.push(writer_group);
        self
    }

    pub fn build(self) -> Publisher {
        // Sanity check
        match self.message_mapping {
            MessageMapping::JSON => {
                debug!("JSON writer should be created")
            }
            MessageMapping::UADP => {
                debug!("UADP writer should be created")
            }
        }
        match self.connection_config {
            ConnectionConfig::Empty => {
                panic!("Can't create a publisher, connection configuration has not been set")
            }
            #[cfg(feature = "pubsub-mqtt")]
            ConnectionConfig::MQTT(_) => {
                debug!("Create an MQTT publisher")
            }
        }
        // Create publisher
        Publisher {
            connection_config: self.connection_config,
            message_mapping: self.message_mapping,
            writer_groups: self.writer_groups,
        }
    }
}
