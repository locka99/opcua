///! Helpers for NotificationMessage types

use crate::{
    date_time::DateTime,
    encoding::DecodingLimits,
    extension_object::ExtensionObject,
    node_ids::ObjectId,
    status_code::StatusCode,
    diagnostic_info::DiagnosticInfo,
    service_types::{
        NotificationMessage, EventNotificationList, EventFieldList, MonitoredItemNotification,
        DataChangeNotification, StatusChangeNotification,
    },
};

impl NotificationMessage {
    /// Create a notification message which contains data change AND / OR events. Calling this with
    /// neither will panic. Notification data can have up to 2 elements to covers the case in
    /// table 158 where a subscription contains monitored items for events and data.
    pub fn data_change(sequence_number: u32, publish_time: DateTime, data_change_notifications: Vec<MonitoredItemNotification>, event_notifications: Vec<EventFieldList>) -> NotificationMessage {

        if data_change_notifications.is_empty() && event_notifications.is_empty() {
            panic!("No notifications supplied to data_change()");
        }

        let mut notification_data = Vec::with_capacity(2);
        if !data_change_notifications.is_empty() {
            let data_change_notification = DataChangeNotification {
                monitored_items: Some(data_change_notifications),
                diagnostic_infos: None,
            };
            trace!("data change notification = {:?}", data_change_notification);
            notification_data.push(ExtensionObject::from_encodable(ObjectId::DataChangeNotification_Encoding_DefaultBinary, &data_change_notification));
        }
        if !event_notifications.is_empty() {
            let event_notification_list = EventNotificationList {
                events: Some(event_notifications)
            };
            trace!("event notification = {:?}", event_notification_list);
            notification_data.push(ExtensionObject::from_encodable(ObjectId::EventNotificationList_Encoding_DefaultBinary, &event_notification_list));
        }

        // Both data and events are serialized
        NotificationMessage {
            sequence_number,
            publish_time,
            notification_data: Some(notification_data),
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
        // TODO this needs to extract events
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
