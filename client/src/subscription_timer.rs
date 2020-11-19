// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2020 Adam Lock

use std::{
    sync::{Arc, RwLock},
    thread,
    time::Duration,
};

use futures::{
    channel::mpsc::{unbounded, UnboundedSender},
    StreamExt,
};

use crate::{session_state::SessionState, subscription_state::SubscriptionState};

#[derive(Clone, Copy, PartialEq)]
pub(crate) enum SubscriptionTimerCommand {
    CreateTimer(u32),
    Quit,
}

pub(crate) struct SubscriptionTimer {
    subscription_id: u32,
    session_state: Arc<RwLock<SessionState>>,
    subscription_state: Arc<RwLock<SubscriptionState>>,
    cancel: bool,
}

impl SubscriptionTimer {
    /// Spawn a thread that waits on a queue for commands to create new subscription timers, or
    /// to quit.
    ///
    /// Each subscription timer spawned by the thread runs as a timer task associated with a
    /// subscription. The subscription timer is responsible for publish requests to the server.
    pub(crate) fn make_timer_command_queue(
        session_state: Arc<RwLock<SessionState>>,
        subscription_state: Arc<RwLock<SubscriptionState>>,
    ) -> UnboundedSender<SubscriptionTimerCommand> {
        let (timer_command_queue, mut timer_receiver) = unbounded::<SubscriptionTimerCommand>();
        let _ = thread::spawn(move || {
            let timer_task = async move {
                while let Some(cmd) = timer_receiver.next().await {
                    if cmd == SubscriptionTimerCommand::Quit {
                        return;
                    }
                    if let SubscriptionTimerCommand::CreateTimer(subscription_id) = cmd {
                        let timer = Arc::new(RwLock::new(SubscriptionTimer {
                            subscription_id,
                            session_state: session_state.clone(),
                            subscription_state: subscription_state.clone(),
                            cancel: false,
                        }));
                        {
                            let mut subscription_state =
                                trace_write_lock_unwrap!(subscription_state);
                            subscription_state.add_subscription_timer(timer.clone());
                        }
                        let timer_task = Self::make_subscription_timer(timer);
                        tokio::spawn(timer_task);
                    }
                }
                info!("Timer receiver has terminated");
            };
            tokio_compat::run_std(timer_task);
        });
        timer_command_queue
    }
    fn call_make_subscription_timer(timer: Arc<RwLock<SubscriptionTimer>>) {
        tokio::spawn(Self::make_subscription_timer(timer));
    }
    /// Makes a future that publishes requests for the subscription. This code doesn't return "impl Future"
    /// due to recursive behaviour in the take_while, so instead it returns a boxed future.
    async fn make_subscription_timer(timer: Arc<RwLock<SubscriptionTimer>>) {
        let publishing_interval = {
            let (subscription_id, subscription_state) = {
                let timer = trace_read_lock_unwrap!(timer);
                (timer.subscription_id, timer.subscription_state.clone())
            };

            let ss = trace_read_lock_unwrap!(subscription_state);
            if let Some(subscription) = ss.get(subscription_id) {
                subscription.publishing_interval()
            } else {
                error!(
                    "Cannot start timer for subscription id {}, doesn't exist",
                    subscription_id
                );
                100.0
            }
        };

        let timer_for_take = timer.clone();

        debug!("Publishing interval {}", publishing_interval);
        let mut interval = tokio::time::interval_at(
            tokio::time::Instant::now(),
            Duration::from_millis(publishing_interval as u64),
        );
        loop {
            interval.tick().await;
            trace!("publishing_interval.take_while");
            let (cancel, subscription_id, subscription_state) = {
                let timer = trace_read_lock_unwrap!(timer_for_take);
                (
                    timer.cancel,
                    timer.subscription_id,
                    timer.subscription_state.clone(),
                )
            };
            let (take, respawn) = {
                if cancel {
                    debug!("Subscription timer for subscription id {} is being dropped because it was cancelled", subscription_id);
                    (false, false)
                } else {
                    let subscription_state = trace_read_lock_unwrap!(subscription_state);
                    if let Some(ref subscription) = subscription_state.get(subscription_id) {
                        if publishing_interval != subscription.publishing_interval() {
                            // Interval has changed, so don't take the timer, and instead
                            // spawn a new timer
                            debug!("Subscription timer for subscription {} is respawning at a new interval {}", subscription_id, subscription.publishing_interval());
                            (false, true)
                        } else {
                            // Take the timer
                            (true, false)
                        }
                    } else {
                        // Subscription has gone and so should the timer
                        debug!("Subscription timer for subscription id {} is being dropped because subscription no longer exists", subscription_id);
                        (false, false)
                    }
                }
            };
            if respawn {
                //error[E0391]: cycle detected when computing type
                Self::call_make_subscription_timer(timer_for_take.clone());
            }
            if !take {
                break; //stop timer
            }
            // Server may have throttled publish requests
            let (subscription_id, session_state) = {
                let timer = trace_read_lock_unwrap!(timer);
                (timer.subscription_id, timer.session_state.clone())
            };

            let wait_for_publish_response = {
                let session_state = trace_read_lock_unwrap!(session_state);
                session_state.wait_for_publish_response()
            };
            if !wait_for_publish_response {
                // We could not send the publish request if subscription is not reporting, or
                // contains no monitored items but it probably makes no odds.
                debug!(
                    "Subscription timer for {} is sending a publish",
                    subscription_id
                );
                let mut session_state = trace_write_lock_unwrap!(session_state);
                // Send a publish request with any acknowledgements
                let subscription_acknowledgements = session_state.subscription_acknowledgements();
                let _ = session_state.async_publish(&subscription_acknowledgements);
            }
        }
        info!("Subscription timer task is finished");
    }

    pub fn subscription_id(&self) -> u32 {
        self.subscription_id
    }

    pub fn cancel(&mut self) {
        self.cancel = true;
    }
}
