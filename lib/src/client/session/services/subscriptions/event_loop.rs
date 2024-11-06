use std::sync::Arc;

use futures::{future::Either, stream::FuturesUnordered, Future, Stream, StreamExt};
use tokio::{
    sync::watch,
    time::{sleep_until, Instant},
};

use crate::{
    client::{
        session::{session_debug, session_error},
        Session,
    },
    types::StatusCode,
};

/// An event on the subscription event loop.
#[derive(Debug)]
pub enum SubscriptionActivity {
    /// A publish request received a successful response.
    Publish,
    /// A publish request failed, either due to a timeout or an error.
    /// The publish request will typically be retried.
    PublishFailed(StatusCode),
}

/// An event loop for running periodic subscription tasks.
///
/// This handles publshing on a fixed interval, republishing failed requests,
/// and subscription keep-alive.
pub struct SubscriptionEventLoop {
    session: Arc<Session>,
    max_inflight_publish: usize,
    last_external_trigger: Instant,
    trigger_publish_rx: watch::Receiver<Instant>,
    // This is true if the client has received a message BadTooManyPublishRequests
    // and is waiting for a response before making further requests.
    is_waiting_for_response: bool,
}

impl SubscriptionEventLoop {
    /// Create a new subscription event loop for `session`
    ///
    /// # Arguments
    ///
    ///  * `session` - A shared reference to an [AsyncSession].
    ///  * `trigger_publish_recv` - A channel used to transmit external publish triggers.
    ///    This is used to trigger publish outside of the normal schedule, for example when
    ///    a new subscription is created.
    pub fn new(session: Arc<Session>, trigger_publish_rx: watch::Receiver<Instant>) -> Self {
        let last_external_trigger = *trigger_publish_rx.borrow();
        Self {
            max_inflight_publish: session.max_inflight_publish,
            session,
            last_external_trigger,
            trigger_publish_rx,
            is_waiting_for_response: false,
        }
    }

    /// Run the subscription event loop, returning a stream that produces
    /// [SubscriptionActivity] enums, reporting activity to the session event loop.
    pub fn run(self) -> impl Stream<Item = SubscriptionActivity> {
        futures::stream::unfold(
            (self, FuturesUnordered::new()),
            |(mut slf, mut futures)| async move {
                // Store the next publish time, or None if there are no active subscriptions.
                let mut next = slf.session.next_publish_time(false);
                let mut recv = slf.trigger_publish_rx.clone();

                let res = loop {
                    // Future for the next periodic publish. We do not send publish requests if there
                    // are no active subscriptions. In this case we return the non-terminating future.
                    let next_tick_fut = if let Some(next) = next {
                        if slf.is_waiting_for_response && !futures.is_empty() {
                            Either::Right(futures::future::pending::<()>())
                        } else {
                            Either::Left(sleep_until(next))
                        }
                    } else {
                        Either::Right(futures::future::pending::<()>())
                    };
                    // If FuturesUnordered is empty, it will immediately yield `None`. We don't
                    // want that, so if it is empty we return the non-terminating future.
                    let next_publish_fut = if futures.is_empty() {
                        Either::Left(futures::future::pending())
                    } else {
                        Either::Right(futures.next())
                    };

                    tokio::select! {
                        // Both internal ticks and external triggers result in publish requests.
                        v = recv.wait_for(|i| i > &slf.last_external_trigger) => {
                            if let Ok(v) = v {
                                debug!("Sending publish due to external trigger");
                                // On an external trigger, we always publish.
                                futures.push(slf.static_publish());
                                next = slf.session.next_publish_time(true);
                                slf.last_external_trigger = *v;
                            }
                        }
                        _ = next_tick_fut => {
                            // Avoid publishing if there are too many inflight publish requests.
                            if futures.len() < slf.max_inflight_publish {
                                debug!("Sending publish due to internal tick");
                                futures.push(slf.static_publish());
                            }
                            next = slf.session.next_publish_time(true);
                        }
                        res = next_publish_fut => {
                            match res {
                                Some(Ok(should_publish_now)) => {
                                    if should_publish_now {
                                        futures.push(slf.static_publish());
                                        // Set the last publish time.
                                        // We do this to avoid a buildup of publish requests
                                        // if exhausting the queue takes more time than
                                        // a single publishing interval.
                                        slf.session.next_publish_time(true);
                                    }
                                    slf.is_waiting_for_response = false;

                                    break SubscriptionActivity::Publish
                                }
                                Some(Err(e)) => {
                                    match e {
                                        StatusCode::BadTimeout => {
                                            session_debug!(slf.session, "Publish request timed out, sending another");
                                            if futures.len() < slf.max_inflight_publish {
                                                futures.push(slf.static_publish());
                                            }
                                        }
                                        StatusCode::BadTooManyPublishRequests => {
                                            session_debug!(slf.session, "Server returned BadTooManyPublishRequests, backing off");
                                            slf.is_waiting_for_response = true;
                                        }
                                        StatusCode::BadSessionClosed
                                        | StatusCode::BadSessionIdInvalid => {
                                            // TODO: Do something here?
                                            session_error!(slf.session, "Publish response indicates session is dead");
                                        }
                                        StatusCode::BadNoSubscription
                                        | StatusCode::BadSubscriptionIdInvalid => {
                                            // TODO: Maybe do something here? This could happen when subscriptions are
                                            // in the process of being recreated. Make sure to avoid race conditions.
                                            session_error!(slf.session, "Publish response indicates subscription is dead");
                                        }
                                        _ => ()
                                    }
                                    break SubscriptionActivity::PublishFailed(e)
                                }
                                // Should be impossible
                                None => break SubscriptionActivity::PublishFailed(StatusCode::BadInvalidState)
                            }
                        }
                    }
                };

                Some((res, (slf, futures)))
            },
        )
    }

    fn static_publish(&self) -> impl Future<Output = Result<bool, StatusCode>> + 'static {
        let inner_session = self.session.clone();
        async move { inner_session.publish().await }
    }
}
