use std::{
    collections::{BTreeSet, VecDeque},
    time::{Duration, Instant},
};

use crate::{
    async_server::info::ServerInfo,
    server::prelude::{
        DataChangeFilter, DataValue, DecodingOptions, EventFieldList, EventFilter, ExtensionObject,
        MonitoredItemCreateRequest, MonitoredItemModifyRequest, MonitoredItemNotification,
        MonitoringMode, ObjectId, ReadValueId, StatusCode, TimestampsToReturn,
    },
};

#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum Notification {
    MonitoredItemNotification(MonitoredItemNotification),
    Event(EventFieldList),
}

impl From<MonitoredItemNotification> for Notification {
    fn from(v: MonitoredItemNotification) -> Self {
        Notification::MonitoredItemNotification(v)
    }
}

impl From<EventFieldList> for Notification {
    fn from(v: EventFieldList) -> Self {
        Notification::Event(v)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) enum FilterType {
    None,
    DataChangeFilter(DataChangeFilter),
    EventFilter(EventFilter),
}

impl FilterType {
    pub fn from_filter(
        filter: &ExtensionObject,
        decoding_options: &DecodingOptions,
    ) -> Result<FilterType, StatusCode> {
        // Check if the filter is a supported filter type
        let filter_type_id = &filter.node_id;
        if filter_type_id.is_null() {
            // No data filter was passed, so just a dumb value comparison
            Ok(FilterType::None)
        } else if let Ok(filter_type_id) = filter_type_id.as_object_id() {
            match filter_type_id {
                ObjectId::DataChangeFilter_Encoding_DefaultBinary => {
                    Ok(FilterType::DataChangeFilter(
                        filter.decode_inner::<DataChangeFilter>(decoding_options)?,
                    ))
                }
                ObjectId::EventFilter_Encoding_DefaultBinary => Ok(FilterType::EventFilter(
                    filter.decode_inner::<EventFilter>(decoding_options)?,
                )),
                _ => {
                    error!(
                        "Requested data filter type is not supported, {:?}",
                        filter_type_id
                    );
                    Err(StatusCode::BadFilterNotAllowed)
                }
            }
        } else {
            error!(
                "Requested data filter type is not an object id, {:?}",
                filter_type_id
            );
            Err(StatusCode::BadFilterNotAllowed)
        }
    }
}

#[derive(Debug)]
pub struct MonitoredItem {
    id: u32,
    item_to_monitor: ReadValueId,
    monitoring_mode: MonitoringMode,
    // Triggered items are other monitored items in the same subscription which are reported if this
    // monitored item changes.
    triggered_items: BTreeSet<u32>,
    client_handle: u32,
    sampling_interval: f64,
    filter: FilterType,
    discard_oldest: bool,
    queue_size: usize,
    notification_queue: VecDeque<Notification>,
    queue_overflow: bool,
    timestamps_to_return: TimestampsToReturn,
    last_sample_time: Instant,
    last_data_value: Option<DataValue>,
}

impl MonitoredItem {
    pub fn new(
        id: u32,
        timestamps_to_return: TimestampsToReturn,
        request: &MonitoredItemCreateRequest,
        info: &ServerInfo,
    ) -> Result<Self, StatusCode> {
        let filter = FilterType::from_filter(
            &request.requested_parameters.filter,
            &info.decoding_options(),
        )?;

        let sampling_interval =
            Self::sanitize_sampling_interval(info, request.requested_parameters.sampling_interval);
        let queue_size =
            Self::sanitize_queue_size(info, request.requested_parameters.queue_size as usize);

        Ok(Self {
            id,
            item_to_monitor: request.item_to_monitor.clone(),
            monitoring_mode: request.monitoring_mode,
            triggered_items: BTreeSet::new(),
            client_handle: request.requested_parameters.client_handle,
            sampling_interval,
            filter,
            discard_oldest: request.requested_parameters.discard_oldest,
            timestamps_to_return,
            last_sample_time: Instant::now(),
            last_data_value: None,
            queue_size,
            notification_queue: VecDeque::new(),
            queue_overflow: false,
        })
    }

    /// Modifies the existing item with the values of the modify request. On success, the result
    /// holds the filter result.
    pub fn modify(
        &mut self,
        info: &ServerInfo,
        timestamps_to_return: TimestampsToReturn,
        request: &MonitoredItemModifyRequest,
    ) -> Result<ExtensionObject, StatusCode> {
        self.timestamps_to_return = timestamps_to_return;
        self.filter = FilterType::from_filter(
            &request.requested_parameters.filter,
            &info.decoding_options(),
        )?;
        self.sampling_interval =
            Self::sanitize_sampling_interval(info, request.requested_parameters.sampling_interval);
        self.queue_size =
            Self::sanitize_queue_size(info, request.requested_parameters.queue_size as usize);
        self.client_handle = request.requested_parameters.client_handle;
        self.discard_oldest = request.requested_parameters.discard_oldest;

        // Shrink / grow the notification queue to the new threshold
        if self.notification_queue.len() > self.queue_size {
            // Discard old notifications
            let discard = self.queue_size - self.notification_queue.len();
            let _ = self.notification_queue.drain(0..discard);
            // TODO potential edge case with discard oldest behaviour
            // Shrink the queue
            self.notification_queue.shrink_to_fit();
        } else if self.notification_queue.capacity() < self.queue_size {
            // Reserve space for more elements
            let extra_capacity = self.queue_size - self.notification_queue.capacity();
            self.notification_queue.reserve(extra_capacity);
        }
        // Validate the filter, return that from this function
        // TODO:
        // self.validate_filter(address_space)
        Ok(ExtensionObject::null())
    }

    pub fn notify_data_value(&mut self, value: DataValue) {
        if self.monitoring_mode == MonitoringMode::Disabled {
            return;
        }
    }

    fn enqueue_notification(&mut self, notification: impl Into<Notification>) {
        let overflow = self.notification_queue.len() == self.queue_size;
        if overflow {
            if self.discard_oldest {
                self.notification_queue.pop_front();
            } else {
                self.notification_queue.pop_back();
            }
        }

        let mut notification = notification.into();
        if overflow {
            if let Notification::MonitoredItemNotification(n) = &mut notification {
                n.value.status = Some(n.value.status().set_overflow(true));
            }
        }
    }

    /// Adds or removes other monitored items which will be triggered when this monitored item changes
    pub fn set_triggering(&mut self, items_to_add: &[u32], items_to_remove: &[u32]) {
        // Spec says to process remove items before adding new ones.
        items_to_remove.iter().for_each(|i| {
            self.triggered_items.remove(i);
        });
        items_to_add.iter().for_each(|i| {
            self.triggered_items.insert(*i);
        });
    }

    /// Takes the requested sampling interval value supplied by client and ensures it is within
    /// the range supported by the server
    fn sanitize_sampling_interval(info: &ServerInfo, requested_sampling_interval: f64) -> f64 {
        if requested_sampling_interval < 0.0 {
            // From spec "any negative number is interpreted as -1"
            // -1 means monitored item's sampling interval defaults to the subscription's publishing interval
            -1.0
        } else if requested_sampling_interval == 0.0
            || requested_sampling_interval < info.min_sampling_interval_ms
        {
            info.min_sampling_interval_ms
        } else {
            requested_sampling_interval
        }
    }

    /// Takes the requested queue size and ensures it is within the range supported by the server
    fn sanitize_queue_size(info: &ServerInfo, requested_queue_size: usize) -> usize {
        if requested_queue_size == 0 || requested_queue_size == 1 {
            // For data monitored items 0 -> 1
            // Future - for event monitored items, queue size should be the default queue size for event notifications
            1
        // Future - for event monitored items, the minimum queue size the server requires for event notifications
        } else if requested_queue_size > info.max_monitored_item_queue_size {
            info.max_monitored_item_queue_size
        // Future - for event monitored items MaxUInt32 returns the maximum queue size the server support
        // for event notifications
        } else {
            requested_queue_size
        }
    }
}
