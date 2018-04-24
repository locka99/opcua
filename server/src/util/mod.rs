use time;
use timer;

/// This is a convenience for a polling action. This struct starts a repeating timer that calls
/// an action repeatedly.
pub struct PollingAction {
    timer: timer::Timer,
    timer_guard: timer::Guard,
}

impl PollingAction {
    pub fn new<F>(interval_ms: u32, action: F) -> PollingAction
        where F: 'static + FnMut() + Send
    {
        let timer = timer::Timer::new();
        let timer_guard = timer.schedule_repeating(time::Duration::milliseconds(interval_ms as i64), action);
        PollingAction {
            timer,
            timer_guard,
        }
    }
}
