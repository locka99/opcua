use opcua_core::types::*;
use opcua_core::services::*;

use address_space::*;
use subscriptions::*;

fn test_var_node_id() -> NodeId {
    NodeId::new_numeric(1, 1)
}

fn make_address_space() -> AddressSpace {
    let mut address_space = AddressSpace::new();
    address_space.add_variable(&Variable::new(&NodeId::new_numeric(1, 1), "test", "test", &DataTypeId::Boolean, DataValue::new(Variant::Boolean(true))), &AddressSpace::objects_folder_id());
    address_space
}

fn make_create_request(sampling_interval: Duration, queue_size: UInt32) -> MonitoredItemCreateRequest {
    // Encode a filter to an extension object
    let data_change_filter = DataChangeFilter {
        trigger: DataChangeTrigger::StatusValueTimestamp,
        deadband_type: 0,
        deadband_value: 0f64,
    };

    let filter = ExtensionObject::from_encodable(ObjectId::DataChangeFilter_Encoding_DefaultBinary.as_node_id(), &data_change_filter);

    MonitoredItemCreateRequest {
        item_to_monitor: ReadValueId {
            node_id: test_var_node_id(),
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
    // create an address space
    let address_space = make_address_space();

    // TODO create a variable & add to address space

    // TODO create request should monitor attribute of variable, e.g. value
    let create_request = make_create_request(1000f64, 5);
    let mut monitored_item = MonitoredItem::new(1, &create_request);

    let now = DateTime::now().as_chrono();
    monitored_item.tick(&address_space, &now, false);

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
fn monitored_item_event_filter() {}

#[test]
fn monitored_aggregate_filter() {}