// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2020 Adam Lock

///! Helpers for NotificationMessage types
use crate::{
    date_time::DateTime,
    diagnostic_info::DiagnosticInfo,
    encoding::DecodingLimits,
    extension_object::ExtensionObject,
    node_id::NodeId,
    node_ids::ObjectId,
    service_types::{
        DataChangeNotification, EventFieldList, EventNotificationList, MonitoredItemNotification,
        NotificationMessage, StatusChangeNotification,
    },
    status_code::StatusCode,
};

impl NotificationMessage {
    /// Create a notification message which contains data change AND / OR events. Calling this with
    /// neither will panic. Notification data can have up to 2 elements to covers the case in
    /// table 158 where a subscription contains monitored items for events and data.
    pub fn data_change(
        sequence_number: u32,
        publish_time: DateTime,
        data_change_notifications: Vec<MonitoredItemNotification>,
        event_notifications: Vec<EventFieldList>,
    ) -> NotificationMessage {
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
            notification_data.push(ExtensionObject::from_encodable(
                ObjectId::DataChangeNotification_Encoding_DefaultBinary,
                &data_change_notification,
            ));
        }
        if !event_notifications.is_empty() {
            let event_notification_list = EventNotificationList {
                events: Some(event_notifications),
            };
            trace!("event notification = {:?}", event_notification_list);
            notification_data.push(ExtensionObject::from_encodable(
                ObjectId::EventNotificationList_Encoding_DefaultBinary,
                &event_notification_list,
            ));
        }

        // Both data and events are serialized
        NotificationMessage {
            sequence_number,
            publish_time,
            notification_data: Some(notification_data),
        }
    }
    /// Create a status change notification message
    pub fn status_change(
        sequence_number: u32,
        publish_time: DateTime,
        status: StatusCode,
    ) -> NotificationMessage {
        let status_change_notification = StatusChangeNotification {
            status,
            diagnostic_info: DiagnosticInfo::null(),
        };
        let notification_data = ExtensionObject::from_encodable(
            ObjectId::StatusChangeNotification_Encoding_DefaultBinary,
            &status_change_notification,
        );
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

    /// Extract notifications from the message. Unrecognized / unparseable notifications will be
    /// ignored. If there are no notifications, the function will return `None`.
    pub fn notifications(
        &self,
        decoding_limits: &DecodingLimits,
    ) -> Option<(Vec<DataChangeNotification>, Vec<EventNotificationList>)> {
        if let Some(ref notification_data) = self.notification_data {
            let data_change_notification_id: NodeId =
                ObjectId::DataChangeNotification_Encoding_DefaultBinary.into();
            let event_notification_list_id: NodeId =
                ObjectId::EventNotificationList_Encoding_DefaultBinary.into();

            let mut data_changes = Vec::with_capacity(notification_data.len());
            let mut events = Vec::with_capacity(notification_data.len());

            // Build up the notifications
            notification_data.iter().for_each(|n| {
                if n.node_id == data_change_notification_id {
                    if let Ok(v) = n.decode_inner::<DataChangeNotification>(decoding_limits) {
                        data_changes.push(v);
                    }
                } else if n.node_id == event_notification_list_id {
                    if let Ok(v) = n.decode_inner::<EventNotificationList>(decoding_limits) {
                        events.push(v);
                    }
                } else {
                    debug!("Ignoring a notification of type {:?}", n.node_id);
                }
            });
            if data_changes.is_empty() && events.is_empty() {
                None
            } else {
                Some((data_changes, events))
            }
        } else {
            None
        }
    }
}
