///! Helpers for NotificationMessage types

use crate::{
    date_time::DateTime,
    encoding::DecodingLimits,
    extension_object::ExtensionObject,
    node_ids::ObjectId,
    status_code::StatusCode,
    diagnostic_info::DiagnosticInfo,
    service_types::{
        NotificationMessage, EventFieldList, MonitoredItemNotification,
        DataChangeNotification, StatusChangeNotification,
    },
};

impl NotificationMessage {
    /// Create a data change notification message
    pub fn data_change(sequence_number: u32, publish_time: DateTime, monitored_items: Vec<MonitoredItemNotification>) -> NotificationMessage {
        let data_change_notification = DataChangeNotification {
            monitored_items: Some(monitored_items),
            diagnostic_infos: None,
        };

        trace!("data change notification = {:?}", data_change_notification);

        // Serialize to extension object
        let notification_data = ExtensionObject::from_encodable(ObjectId::DataChangeNotification_Encoding_DefaultBinary, &data_change_notification);
        NotificationMessage {
            sequence_number,
            publish_time,
            notification_data: Some(vec![notification_data]),
        }
    }

    /// Create an event notification message
    pub fn event(sequence_number: u32, publish_time: DateTime, event: EventFieldList) -> NotificationMessage {
        // TODO - create an event notification
        NotificationMessage {
            sequence_number,
            publish_time,
            notification_data: None,
        }
    }

    /// Create a status change notification message
    pub fn status_change(sequence_number: u32, publish_time: DateTime, status: StatusCode) -> NotificationMessage {
        let status_change_notification = StatusChangeNotification {
            status,
            diagnostic_info: DiagnosticInfo::null(),
        };
        let notification_data = ExtensionObject::from_encodable(ObjectId::StatusChangeNotification_Encoding_DefaultBinary, &status_change_notification);
        NotificationMessage {
            sequence_number,
            publish_time,
            notification_data: Some(vec![notification_data]),
        }
    }

    /// Create a keep-alive notification message
    pub fn keep_alive(sequence_number: u32, publish_time: DateTime) -> NotificationMessage {
        NotificationMessage {
            sequence_number,
            publish_time,
            notification_data: None,
        }
    }

    /// Extract data change notifications from this notification. That assumes this message
    /// actually contains data change notifications, otherwise it will return an empty list.
    pub fn data_change_notifications(&self, decoding_limits: &DecodingLimits) -> Vec<DataChangeNotification> {
        let mut result = Vec::with_capacity(10);
        if let Some(ref notification_data) = self.notification_data {
            // Dump out the contents
            for n in notification_data {
                if n.node_id != ObjectId::DataChangeNotification_Encoding_DefaultBinary.into() {
                    continue;
                }
                if let Ok(notification) = n.decode_inner::<DataChangeNotification>(decoding_limits) {
                    result.push(notification);
                }
            }
        }
        result
    }
}
