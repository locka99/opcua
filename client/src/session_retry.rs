use std::time::{Duration, Instant};

#[derive(PartialEq, Debug)]
pub enum Answer {
    Retry,
    WaitFor(Duration),
    GiveUp,
}

#[derive(PartialEq, Debug, Clone)]
pub struct SessionRetry {
    /// Retry max limit, 0 for no limit
    retry_limit: u32,
    /// Interval between retries
    retry_interval: Duration,
}

impl Default for SessionRetry {
    fn default() -> Self {
        SessionRetry {
            retry_limit: Self::DEFAULT_RETRY_LIMIT,
            retry_interval: Duration::from_millis(Self::DEFAULT_RETRY_INTERVAL_MS),
        }
    }
}

impl SessionRetry {
    pub const DEFAULT_RETRY_LIMIT: u32 = 10;
    pub const DEFAULT_RETRY_INTERVAL_MS: u64 = 10000;

    /// Asks the policy, given the last retry attempt, should we try to connect again, wait a period of time
    /// or give up entirely.
    pub fn should_retry_connect(&self, number_of_attempts: u32, now: Instant, last_attempt: Instant) -> Answer {
        if self.retry_limit > 0 && number_of_attempts > self.retry_limit {
            // Number of retries have been exceeded
            Answer::GiveUp
        } else {
            // Look at how much time has elapsed since the last attempt
            let elapsed = now - last_attempt;
            if self.retry_interval > elapsed {
                // Wait a bit
                Answer::WaitFor(self.retry_interval - elapsed)
            } else {
                //
                Answer::Retry
            }
        }
    }
}

#[test]
fn session_retry() {
    let session_retry = SessionRetry::default();

    let now = Instant::now();

    let retry_interval = Duration::from_millis(SessionRetry::DEFAULT_RETRY_INTERVAL_MS);
    let last_attempt_expired = now - retry_interval + Duration::new(0, 1);
    let last_attempt_wait = now - retry_interval + Duration::new(1, 0);

    assert_eq!(session_retry.should_retry_connect(1, now, last_attempt_expired), Answer::Retry);
    assert_eq!(session_retry.should_retry_connect(SessionRetry::DEFAULT_RETRY_LIMIT, now, last_attempt_expired), Answer::Retry);
    assert_eq!(session_retry.should_retry_connect(SessionRetry::DEFAULT_RETRY_LIMIT + 1, now, last_attempt_expired), Answer::GiveUp);

    assert_eq!(session_retry.should_retry_connect(1, now, last_attempt_wait), Answer::WaitFor(Duration::new(1, 0)));
}