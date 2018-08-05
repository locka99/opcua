///! Helpers for NotificationMessage types
use std;
use std::sync::Mutex;

use date_time::DateTime;
use basic_types::*;
use extension_object::ExtensionObject;
use node_ids::ObjectId;
use service_types::{NotificationMessage, MonitoredItemNotification, DataChangeNotification};

lazy_static! {
    static ref SEQUENCE_NUMBER: Mutex<UInt32> = Mutex::new(1);
}

impl NotificationMessage {
    fn next_sequence_number() -> UInt32 {
        let sequence_number = { *SEQUENCE_NUMBER.lock().unwrap() };
        *SEQUENCE_NUMBER.lock().unwrap() = sequence_number;
        sequence_number
    }

    pub fn data_change(publish_time: DateTime, monitored_items: Vec<MonitoredItemNotification>) -> NotificationMessage {
        let data_change_notification = DataChangeNotification {
            monitored_items: Some(monitored_items),
            diagnostic_infos: None,
        };

        trace!("data change notification = {:?}", data_change_notification);

        // Serialize to extension object
        let notification_data = ExtensionObject::from_encodable(ObjectId::DataChangeNotification_Encoding_DefaultBinary, data_change_notification);
        let sequence_number = Self::next_sequence_number();
        NotificationMessage {
            sequence_number,
            publish_time,
            notification_data: Some(vec![notification_data]),
        }
    }

    pub fn keep_alive(publish_time: DateTime) -> NotificationMessage {
        let sequence_number = Self::next_sequence_number();
        NotificationMessage {
            sequence_number,
            publish_time,
            notification_data: None,
        }
    }

    pub fn data_change_notifications(&self) -> Vec<DataChangeNotification> {
        let mut result = Vec::with_capacity(10);
        if let Some(ref notification_data) = self.notification_data {
            // Dump out the contents
            for n in notification_data {
                if n.node_id != ObjectId::DataChangeNotification_Encoding_DefaultBinary.into() {
                    continue;
                }
                result.push(n.decode_inner::<DataChangeNotification>().unwrap());
            }
        }
        result
    }
}
