use std;

use futures::Future;
use futures::Stream;
use tokio;
use tokio_timer;

/// This is a convenience for a polling action. This struct starts a repeating timer that calls
/// an action repeatedly.
pub struct PollingAction {}

impl PollingAction {
    pub fn spawn<F>(interval_ms: u32, action: F) -> PollingAction
        where F: 'static + Fn() + Send
    {
        let f = tokio_timer::Timer::default()
            .interval(std::time::Duration::from_millis(interval_ms as u64))
            .for_each(move |_| {
                action();
                Ok(())
            })
            .map_err(|_| ());
        let _ = tokio::spawn(f);
        PollingAction {}
    }
}
