use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
    time::{Duration, Instant},
};

use crate::{
    async_server::authenticator::UserToken, core::handle::AtomicHandle,
    server::prelude::NotificationMessage,
};

use super::monitored_item::MonitoredItem;

#[derive(Debug, Copy, Clone, PartialEq)]
pub(crate) enum SubscriptionState {
    Closed,
    Creating,
    Normal,
    Late,
    KeepAlive,
}

#[derive(Debug)]
pub struct Subscription {
    id: u32,
    publishing_interval: Duration,
    max_lifetime_counter: u32,
    max_keep_alive_counter: u32,
    priority: u8,
    monitored_items: HashMap<u32, MonitoredItem>,
    /// State of the subscription
    state: SubscriptionState,
    /// A value that contains the number of consecutive publishing timer expirations without Client
    /// activity before the Subscription is terminated.
    lifetime_counter: u32,
    /// Keep alive counter decrements when there are no notifications to publish and when it expires
    /// requests to send an empty notification as a keep alive event
    keep_alive_counter: u32,
    /// boolean value that is set to true to mean that either a NotificationMessage or a keep-alive
    /// Message has been sent on the Subscription. It is a flag that is used to ensure that either
    /// a NotificationMessage or a keep-alive Message is sent out the first time the publishing timer
    /// expires.
    first_message_sent: bool,
    /// The parameter that requests publishing to be enabled or disabled.
    publishing_enabled: bool,
    /// A flag that tells the subscription to send the latest value of every monitored item on the
    /// next publish request.
    resend_data: bool,
    /// The next sequence number to be sent
    sequence_number: AtomicHandle,
    /// Last notification's sequence number. This is a sanity check since sequence numbers should start from
    /// 1 and be sequential - it that doesn't happen the server will panic because something went
    /// wrong somewhere.
    last_sequence_number: u32,
    // The last monitored item id
    next_monitored_item_id: u32,
    // The time that the subscription interval last fired
    last_time_publishing_interval_elapsed: Instant,
    // Currently outstanding notifications to send
    notifications: VecDeque<NotificationMessage>,
    /// Identity token of the user that created the subscription, used for transfer subscriptions.
    user_token: UserToken,
    /// Application URI of the user that created the subscription, used for transfer subscriptions if
    /// the identity token is anonymous.
    application_uri: String,
}

impl Subscription {}
