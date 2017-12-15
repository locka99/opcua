use prelude::*;

use opcua_core;

use services::subscription::SubscriptionService;
use services::monitored_item::MonitoredItemService;

use super::*;

fn create_subscription_request() -> CreateSubscriptionRequest {
    CreateSubscriptionRequest {
        request_header: RequestHeader::new(&NodeId::null(), &DateTime::now(), 1),
        requested_publishing_interval: 100f64,
        requested_lifetime_count: 100,
        requested_max_keep_alive_count: 100,
        max_notifications_per_publish: 5,
        publishing_enabled: true,
        priority: 0,
    }
}

fn create_monitored_items_request<T>(subscription_id: UInt32, node_id: T) -> CreateMonitoredItemsRequest where T: 'static + Into<NodeId> {
    CreateMonitoredItemsRequest {
        request_header: RequestHeader::new(&NodeId::null(), &DateTime::now(), 1),
        subscription_id: subscription_id,
        timestamps_to_return: TimestampsToReturn::Both,
        items_to_create: Some(vec![MonitoredItemCreateRequest {
            item_to_monitor: ReadValueId {
                node_id: node_id.into(),
                attribute_id: AttributeId::Value as UInt32,
                index_range: UAString::null(),
                data_encoding: QualifiedName::null(),
            },
            monitoring_mode: MonitoringMode::Reporting,
            requested_parameters: MonitoringParameters {
                client_handle: 1,
                sampling_interval: 0.1,
                filter: ExtensionObject::null(),
                queue_size: 1,
                discard_oldest: true,
            },
        }]),
    }
}

#[test]
fn publish_response_subscription() {
    opcua_core::init_logging();

    // Create a session
    let st = ServiceTest::new();
    let (mut server_state, mut session) = st.get_server_state_and_session();

    // Create a subscription with a monitored item
    let ss = SubscriptionService::new();
    let mis = MonitoredItemService::new();

    let request = create_subscription_request();
    debug!("{:#?}", request);
    let response = expect_message!(ss.create_subscription(&mut server_state, &mut session, request).unwrap(), CreateSubscriptionResponse);
    debug!("{:#?}", response);

    let request = create_monitored_items_request(response.subscription_id, VariableId::Server_ServerStatus_CurrentTime);
    debug!("{:#?}", request);
    let response = expect_message!(mis.create_monitored_items(&mut session, request).unwrap(), CreateMonitoredItemsResponse);
    debug!("{:#?}", response);

    // Tick a change on the monitored item
    // TODOcar

    // Send a publish and expect a publish response containing the subscription
    let request_id = 1001;
    let mut address_space = st.get_address_space();
    let request = PublishRequest {
        request_header: RequestHeader::new(&NodeId::null(), &DateTime::now(), 1),
        subscription_acknowledgements: None, // Option<Vec<SubscriptionAcknowledgement>>,
    };
    debug!("{:#?}", request);
    let response = ss.publish(&mut session, request_id, &address_space, request).unwrap();
    if let Some(response) = response {
        let response = expect_message!(response, PublishResponse);
        debug!("{:#?}", response);
    } else {
        debug!("Got no response from publish (i.e. queued)");
    }
}

#[test]
fn multiple_publish_response_subscription() {
    // Create a session
    let st = ServiceTest::new();
    let (mut server_state, mut session) = st.get_server_state_and_session();

    // Create a subscription with a monitored item
    let ss = SubscriptionService::new();
    let mis = MonitoredItemService::new();

    // Send a publish and expect nothing
    // Tick a change
    // Expect a publish response containing the subscription to be pushed
}
