use std::io::{Cursor};

use opcua_core::types::*;
use opcua_core::services::*;

use address_space::*;
use subscriptions::*;

fn make_create_request(sampling_interval: Duration, queue_size: UInt32) -> MonitoredItemCreateRequest {
    // Encode a filter to an extension object
    let data_change_filter = DataChangeFilter {
        trigger: DataChangeTrigger::StatusValueTimestamp,
        deadband_type: 0,
        deadband_value: 0f64,
    };

    let mut cursor = Cursor::new(vec![0u8; data_change_filter.byte_len()]);
    let _ = data_change_filter.encode(&mut cursor);

    let filter = ExtensionObject {
        node_id:  ObjectId::DataChangeFilter_Encoding_DefaultBinary.as_node_id(),
        body: ExtensionObjectEncoding::ByteString(ByteString::from_bytes(&cursor.into_inner())),
    };

    MonitoredItemCreateRequest {
        item_to_monitor: ReadValueId {
            node_id: NodeId::new_numeric(1, 1),
            attribute_id: AttributeId::Value as UInt32,
            index_range: UAString::null(),
            data_encoding: QualifiedName::null(),
        },
        monitoring_mode: MonitoringMode::Reporting,
        requested_parameters: MonitoringParameters {
            client_handle: 999,
            sampling_interval: sampling_interval,
            filter: filter,
            queue_size: queue_size,
            discard_oldest: true,
        },
    }
}

#[test]
fn monitored_item_data_change_filter() {
    // TODO create an address space
    // TODO create a variable & add to address space

    // TODO create request should monitor attribute of variable, e.g. value
    let create_request = make_create_request(1000f64, 5);
    let mut monitored_item = MonitoredItem::new(1, &create_request);

    let now = DateTime::now().as_chrono();
    monitored_item.tick(&now, false);

    // TODO always expect true on first tick

    // TODO always expect false on next tick, with now the same

    // TODO adjust now forward by 1.5s

    // TODO expect tick to be false

    // TODO adjust now forward by 1.5s

    // TODO adjust variable value

    // TODO expect tick to be true

    // TODO check notification queue for 1 value
}

#[test]
fn monitored_item_event_filter() {


}

#[test]
fn monitored_aggregate_filter() {


}