use std::{
    collections::{BTreeSet, VecDeque},
    time::Instant,
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
pub enum FilterType {
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

pub struct CreateMonitoredItem {
    id: u32,
    subscription_id: u32,
    item_to_monitor: ReadValueId,
    monitoring_mode: MonitoringMode,
    client_handle: u32,
    discard_oldest: bool,
    queue_size: usize,
    sampling_interval: f64,
    initial_value: Option<DataValue>,
    status_code: StatusCode,
    filter: FilterType,
    timestamps_to_return: TimestampsToReturn,
}

/// Takes the requested sampling interval value supplied by client and ensures it is within
/// the range supported by the server
fn sanitize_sampling_interval(info: &ServerInfo, requested_sampling_interval: f64) -> f64 {
    if requested_sampling_interval < 0.0 {
        // From spec "any negative number is interpreted as -1"
        // -1 means monitored item's sampling interval defaults to the subscription's publishing interval
        -1.0
    } else if requested_sampling_interval == 0.0
        || requested_sampling_interval < info.config.limits.subscriptions.min_sampling_interval_ms
    {
        info.config.limits.subscriptions.min_sampling_interval_ms
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
    } else if requested_queue_size > info.config.limits.subscriptions.max_monitored_item_queue_size {
        info.config.limits.subscriptions.max_monitored_item_queue_size
    // Future - for event monitored items MaxUInt32 returns the maximum queue size the server support
    // for event notifications
    } else {
        requested_queue_size
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MonitoredItemId {
    pub(crate) monitored_item: u32,
    pub(crate) subscription: u32,
}

impl CreateMonitoredItem {
    pub fn new(
        req: MonitoredItemCreateRequest,
        id: u32,
        sub_id: u32,
        info: &ServerInfo,
        timestamps_to_return: TimestampsToReturn,
    ) -> Result<Self, StatusCode> {
        let filter =
            FilterType::from_filter(&req.requested_parameters.filter, &info.decoding_options())?;
        let sampling_interval =
            sanitize_sampling_interval(info, req.requested_parameters.sampling_interval);
        let queue_size = sanitize_queue_size(info, req.requested_parameters.queue_size as usize);

        Ok(Self {
            id,
            subscription_id: sub_id,
            item_to_monitor: req.item_to_monitor,
            monitoring_mode: req.monitoring_mode,
            client_handle: req.requested_parameters.client_handle,
            discard_oldest: req.requested_parameters.discard_oldest,
            queue_size,
            sampling_interval,
            initial_value: None,
            status_code: StatusCode::Good,
            filter,
            timestamps_to_return,
        })
    }

    pub fn id(&self) -> MonitoredItemId {
        MonitoredItemId {
            monitored_item: self.id,
            subscription: self.subscription_id,
        }
    }

    pub fn set_initial_value(&mut self, value: DataValue) {
        self.initial_value = Some(value);
    }

    pub fn set_status(&mut self, status: StatusCode) {
        self.status_code = status;
    }

    pub fn item_to_monitor(&self) -> &ReadValueId {
        &self.item_to_monitor
    }

    pub fn monitoring_mode_mut(&mut self) -> &mut MonitoringMode {
        &mut self.monitoring_mode
    }

    pub fn sampling_interval(&self) -> f64 {
        self.sampling_interval
    }

    pub fn queue_size(&self) -> usize {
        self.queue_size
    }

    pub fn filter(&self) -> &FilterType {
        &self.filter
    }

    pub fn revise_queue_size(&mut self, queue_size: usize) {
        if queue_size < self.queue_size && queue_size > 0 || self.queue_size == 0 {
            self.queue_size = queue_size;
        }
    }

    pub fn revise_sampling_interval(&mut self, sampling_interval: f64) {
        if sampling_interval < self.sampling_interval && sampling_interval > 0.0
            || self.sampling_interval == 0.0
        {
            self.sampling_interval = sampling_interval;
        }
    }

    pub fn timestamps_to_return(&self) -> TimestampsToReturn {
        self.timestamps_to_return
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
    pub fn new(request: &CreateMonitoredItem) -> Self {
        let mut v = Self {
            id: request.id,
            item_to_monitor: request.item_to_monitor.clone(),
            monitoring_mode: request.monitoring_mode,
            triggered_items: BTreeSet::new(),
            client_handle: request.client_handle,
            sampling_interval: request.sampling_interval,
            filter: request.filter.clone(),
            discard_oldest: request.discard_oldest,
            timestamps_to_return: request.timestamps_to_return,
            last_sample_time: Instant::now(),
            last_data_value: None,
            queue_size: request.queue_size,
            notification_queue: VecDeque::new(),
            queue_overflow: false,
        };
        if let Some(val) = request.initial_value.as_ref() {
            v.notify_data_value(val.clone());
        }
        v
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
            sanitize_sampling_interval(info, request.requested_parameters.sampling_interval);
        self.queue_size =
            sanitize_queue_size(info, request.requested_parameters.queue_size as usize);
        self.client_handle = request.requested_parameters.client_handle;
        self.discard_oldest = request.requested_parameters.discard_oldest;

        // Shrink / grow the notification queue to the new threshold
        if self.notification_queue.len() > self.queue_size {
            // Discard old notifications
            let discard = self.notification_queue.len() - self.queue_size;
            for _ in 0..discard {
                if self.discard_oldest {
                    let _ = self.notification_queue.pop_back();
                } else {
                    let _ = self.notification_queue.pop_front();
                }
            }
            // Shrink the queue
            self.notification_queue.shrink_to_fit();
        }
        // Validate the filter, return that from this function
        // TODO:
        // self.validate_filter(address_space)
        Ok(ExtensionObject::null())
    }

    fn filter_by_sampling_interval(&self, old: &DataValue, new: &DataValue) -> bool {
        let (Some(old), Some(new)) = (&old.source_timestamp, &new.source_timestamp) else {
            // Always include measurements without source timestamp, we don't know enough about these,
            // assume the server implementation did filtering elsewhere.
            return true;
        };

        let elapsed = new.as_chrono().signed_duration_since(old.as_chrono()).to_std().unwrap();
        let sampling_interval = std::time::Duration::from_micros((self.sampling_interval * 1000f64) as u64);
        elapsed >= sampling_interval
    }

    pub fn notify_data_value(&mut self, mut value: DataValue) {
        if self.monitoring_mode == MonitoringMode::Disabled {
            return;
        }

        let data_change = match (&self.last_data_value, &self.filter) {
            (Some(last_dv), FilterType::DataChangeFilter(filter)) => {
                !filter.compare(&value, last_dv, None)
                    && self.filter_by_sampling_interval(last_dv, &value)
            }
            (Some(last_dv), FilterType::None) => value.value != last_dv.value && self.filter_by_sampling_interval(last_dv, &value),
            (None, _) => true,
            _ => false,
        };

        if !data_change {
            return;
        }

        self.last_data_value = Some(value.clone());

        match self.timestamps_to_return {
            TimestampsToReturn::Neither | TimestampsToReturn::Invalid => {
                value.source_timestamp = None;
                value.source_picoseconds = None;
                value.server_timestamp = None;
                value.server_picoseconds = None
            }
            TimestampsToReturn::Server => {
                value.source_timestamp = None;
                value.source_picoseconds = None;
            }
            TimestampsToReturn::Source => {
                value.server_timestamp = None;
                value.server_picoseconds = None
            }
            TimestampsToReturn::Both => {
                // DO NOTHING
            }
        }

        let client_handle = self.client_handle;
        self.enqueue_notification(MonitoredItemNotification {
            client_handle,
            value,
        });
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
            self.queue_overflow = true;
        }
    }

    pub fn drain_notifications<'a>(
        &'a mut self,
        resend_data: bool,
    ) -> impl Iterator<Item = Notification> + 'a {
        if resend_data {
            // Check if the last value is already enqueued
            if !matches!(self.notification_queue.get(0), 
                Some(Notification::MonitoredItemNotification(it))
                    if Some(&it.value) == self.last_data_value.as_ref())
            {
                self.enqueue_notification(Notification::MonitoredItemNotification(MonitoredItemNotification {
                    client_handle: self.client_handle,
                    value: self.last_data_value.clone().unwrap(),
                }))
            }
            
        }

        self.notification_queue.drain(..)
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

    pub fn monitoring_mode(&self) -> MonitoringMode {
        self.monitoring_mode
    }

    pub fn triggered_items(&self) -> &BTreeSet<u32> {
        &self.triggered_items
    }

    pub fn has_notifications(&self) -> bool {
        !self.notification_queue.is_empty()
    }
}
