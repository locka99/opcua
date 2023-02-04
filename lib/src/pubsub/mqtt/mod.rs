use url::Url;

use crate::pubsub::core::network_message::NetworkMessage;
use crate::pubsub::publisher::PublisherTransport;
use rumqttc::{AsyncClient, QoS};

use crate::types::*;

/// MQTT scheme
pub const MQTT_SCHEME: &'static str = "mqtt";

/// Default MQTT port
pub const MQTT_DEFAULT_PORT: u16 = 8333;

/// WSS scheme
pub const WSS_SCHEME: &'static str = "wss";

/// Default secure websocket port
pub const WSS_DEFAULT_PORT: u16 = 443;

#[derive(PartialEq, Debug)]
pub enum Transport {
    Tls,
    Wss,
}

/// Configuration of an MQTT connection
pub struct MQTTConfig {
    transport: Transport,
    domain: String,
    port: u16,
    path: String,
    qos: BrokerTransportQualityOfService,
}

impl TryFrom<&str> for MQTTConfig {
    type Error = ();

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if let Ok(url) = Url::parse(value) {
            let scheme = url.scheme();
            let domain = url.domain().unwrap_or("");
            let path = url.path();
            let qos = BrokerTransportQualityOfService::NotSpecified;
            if scheme == MQTT_SCHEME {
                let port = url.port().unwrap_or(MQTT_DEFAULT_PORT);
                Ok(MQTTConfig::new(Transport::Tls, domain, port, path, qos))
            } else if scheme == WSS_SCHEME {
                let port = url.port().unwrap_or(WSS_DEFAULT_PORT);
                Ok(MQTTConfig::new(Transport::Wss, domain, port, path, qos))
            } else {
                Err(())
            }
        } else {
            error!("Cannot parse MQTT url from {}", value);
            Err(())
        }
    }
}

impl MQTTConfig {
    pub fn new<S, T>(
        transport: Transport,
        domain: S,
        port: u16,
        path: T,
        qos: BrokerTransportQualityOfService,
    ) -> Self
    where
        S: Into<String>,
        T: Into<String>,
    {
        Self {
            transport,
            domain: domain.into(),
            port,
            path: path.into(),
            qos,
        }
    }

    pub fn as_url(&self) -> String {
        let scheme = match self.transport {
            Transport::Tls => MQTT_SCHEME,
            Transport::Wss => WSS_SCHEME,
        };
        if self.port == MQTT_DEFAULT_PORT {
            format!("{}://{}{}", scheme, self.domain, self.path)
        } else {
            format!("{}://{}:{}{}", scheme, self.domain, self.port, self.path)
        }
    }
}

pub struct MQTTPublisherTransport;

impl PublisherTransport for MQTTPublisherTransport {
    fn connect() -> Result<(), ()> {
        todo!()
    }

    fn disconnect() {
        todo!()
    }

    fn publish(message: NetworkMessage) {
        todo!()
    }
}

impl MQTTPublisherTransport {
    pub fn new(config: MQTTConfig) -> Self {
        Self {}
    }
}

#[test]
fn parse_mqtt_url() {
    // Default port
    let cfg = MQTTConfig::try_from("mqtt://foo/xyz").unwrap();
    assert_eq!(cfg.transport, Transport::Tls);
    assert_eq!(cfg.port, MQTT_DEFAULT_PORT);
    assert_eq!(cfg.as_url(), "mqtt://foo/xyz");

    // Other port
    let cfg = MQTTConfig::try_from("mqtt://foo:1234/xyz").unwrap();
    assert_eq!(cfg.transport, Transport::Tls);
    assert_eq!(cfg.domain, "foo");
    assert_eq!(cfg.port, 1234);
    assert_eq!(cfg.path, "/xyz");
    assert_eq!(cfg.as_url(), "mqtt://foo:1234/xyz");

    // Wss
    let cfg = MQTTConfig::try_from("wss://foo/xyz").unwrap();
    assert_eq!(cfg.transport, Transport::Wss);
    assert_eq!(cfg.port, WSS_DEFAULT_PORT);
    assert_eq!(cfg.as_url(), "wss://foo/xyz");

    // Path
    let cfg = MQTTConfig::try_from("mqtt://foo").unwrap();
    assert_eq!(cfg.port, MQTT_DEFAULT_PORT);
    assert_eq!(cfg.path, "/");

    // This is not exhaustive since url parser is tested in its own right
    assert!(MQTTConfig::try_from("mtqq:/").is_err());
    assert!(MQTTConfig::try_from("foo:1234/").is_err());
}

/// Establishes a connection to an MQTT broker
fn connect(config: &MQTTConfig) {
    // Quality of service
    let qos = match config.qos {
        BrokerTransportQualityOfService::AtLeastOnce => QoS::AtLeastOnce,
        BrokerTransportQualityOfService::AtMostOnce => QoS::AtMostOnce,
        BrokerTransportQualityOfService::ExactlyOnce => QoS::ExactlyOnce,
        // Default the rest like so
        BrokerTransportQualityOfService::BestEffort
        | BrokerTransportQualityOfService::NotSpecified => QoS::AtLeastOnce,
    };
    info!("Creating MQTT client with {:?}", qos);
}
