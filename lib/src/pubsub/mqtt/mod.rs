use url::Url;

use crate::pubsub::core::NetworkMessage;
use crate::pubsub::publisher::PublisherTransport;
use rumqttc::{AsyncClient, EventLoop, MqttOptions, QoS};

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
    topic: String,
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
                Ok(MQTTConfig::new(Transport::Tls, domain, port, path, "", qos))
            } else if scheme == WSS_SCHEME {
                let port = url.port().unwrap_or(WSS_DEFAULT_PORT);
                Ok(MQTTConfig::new(Transport::Wss, domain, port, path, "", qos))
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
    pub fn new<S, T, U>(
        transport: Transport,
        domain: S,
        port: u16,
        path: T,
        topic: U,
        qos: BrokerTransportQualityOfService,
    ) -> Self
    where
        S: Into<String>,
        T: Into<String>,
        U: Into<String>,
    {
        Self {
            transport,
            domain: domain.into(),
            port,
            path: path.into(),
            topic: topic.into(),
            qos,
        }
    }

    pub fn as_url(&self) -> String {
        let (scheme, default_port) = match self.transport {
            Transport::Tls => (MQTT_SCHEME, MQTT_DEFAULT_PORT),
            Transport::Wss => (WSS_SCHEME, WSS_DEFAULT_PORT),
        };
        if self.port == default_port {
            format!("{}://{}{}", scheme, self.domain, self.path)
        } else {
            format!("{}://{}:{}{}", scheme, self.domain, self.port, self.path)
        }
    }
}

struct MQTTClient {
    client: AsyncClient,
    event_loop: EventLoop,
}

pub struct MQTTPublisherTransport {
    config: MQTTConfig,
    client: Option<MQTTClient>,
}

/// Max capacity of unbounded channel
const CHANNEL_CAPACITY: usize = 1000;

impl PublisherTransport for MQTTPublisherTransport {
    fn connect(&mut self) -> Result<(), ()> {
        self.disconnect();
        let options =
            MqttOptions::new("OPCUARustMQTTClient", &self.config.domain, self.config.port);
        let cap = CHANNEL_CAPACITY;
        let (client, event_loop) = AsyncClient::new(options, cap);
        self.client = Some(MQTTClient { client, event_loop });
        Ok(())
    }

    fn disconnect(&mut self) {
        if let Some(ref client) = self.client {
            let _ = client.client.disconnect();
        }
        self.client = None;
    }

    fn publish(&mut self, message: Box<dyn NetworkMessage>)
    {
        // TODO writer must be associated with transport, or arrive as a parameter
        if let Some(ref client) = self.client {
            let qos = self.qos();
            let retain = false;

            let payload = "TODO".as_bytes();
            client
                .client
                .publish(&self.config.topic, qos, retain, payload);
        }
    }
}

impl MQTTPublisherTransport {
    pub fn new(config: MQTTConfig) -> Self {
        Self {
            client: None,
            config,
        }
    }

    fn qos(&self) -> QoS {
        match self.config.qos {
            BrokerTransportQualityOfService::AtLeastOnce => QoS::AtLeastOnce,
            BrokerTransportQualityOfService::AtMostOnce => QoS::AtMostOnce,
            BrokerTransportQualityOfService::ExactlyOnce => QoS::ExactlyOnce,
            // Default the rest like so
            BrokerTransportQualityOfService::BestEffort
            | BrokerTransportQualityOfService::NotSpecified => QoS::AtLeastOnce,
        }
    }

    async fn poll(&mut self) {
        let event_loop = &mut self.client.as_mut().unwrap().event_loop;
        let event = event_loop.poll().await;
        match &event {
            Ok(v) => {
                println!("Event = {v:?}");
            }
            Err(e) => {
                println!("Error = {e:?}");
            }
        }
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
