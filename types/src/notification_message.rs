///! Helpers for NotificationMessage types

use date_time::DateTime;
use basic_types::*;
use generated::ObjectId;
use generated::{NotificationMessage, MonitoredItemNotification, DataChangeNotification};

impl NotificationMessage {
    pub fn new_data_change(sequence_number: UInt32, publish_time: &DateTime, monitored_items: Vec<MonitoredItemNotification>) -> NotificationMessage {
        let data_change_notification = DataChangeNotification {
            monitored_items: Some(monitored_items),
            diagnostic_infos: None,
        };

        trace!("data change notification = {:?}", data_change_notification);

        // Serialize to extension object
        let notification_data = ExtensionObject::from_encodable(ObjectId::DataChangeNotification_Encoding_DefaultBinary.as_node_id(), data_change_notification);
        NotificationMessage {
            sequence_number,
            publish_time: publish_time.clone(),
            notification_data: Some(vec![notification_data]),
        }
    }
}