use chrono::{DateTime, TimeZone, Utc};
use time::Duration;

#[derive(PartialEq, Debug)]
pub enum Answer {
    Retry,
    WaitFor(Duration),
    GiveUp,
}

/// The session retry policy determines what the session will do if the connection drops, or it
/// suffers from connectivity issues. The policy allows a session to attempt to reconnect a number
/// of times and to control its retry interval.
#[derive(PartialEq, Debug, Clone)]
pub struct SessionRetryPolicy {
    /// The number of attempts so far
    retry_count: u32,
    /// The last retry attempt
    last_attempt: DateTime<Utc>,
    /// Retry max limit, 0 for no limit
    retry_limit: u32,
    /// Interval between retries
    retry_interval: Duration,
}

impl Default for SessionRetryPolicy {
    fn default() -> Self {
        // Default retry policy
        SessionRetryPolicy {
            retry_count: 0,
            last_attempt: Utc.ymd(1900, 1, 1).and_hms(0, 0, 0),
            retry_limit: Self::DEFAULT_RETRY_LIMIT,
            retry_interval: Duration::milliseconds(Self::DEFAULT_RETRY_INTERVAL_MS),
        }
    }
}

impl SessionRetryPolicy {
    /// The default retry policy will attempt to reconnect up to this many times.
    pub const DEFAULT_RETRY_LIMIT: u32 = 10;
    /// The default retry policy will wait this duration between reconnect attempts.
    pub const DEFAULT_RETRY_INTERVAL_MS: i64 = 2000;

    pub fn increment_retry_count(&mut self) {
        self.retry_count += 1;
    }

    pub fn reset_retry_count(&mut self) {
        self.retry_count = 0;
    }

    pub fn set_last_attempt(&mut self, last_attempt: DateTime<Utc>) {
        self.last_attempt = last_attempt;
    }

    /// Asks the policy, given the last retry attempt, should we try to connect again, wait a period of time
    /// or give up entirely.
    pub fn should_retry_connect(&self, now: DateTime<Utc>) -> Answer {
        if self.retry_limit > 0 && self.retry_count >= self.retry_limit {
            // Number of retries have been exceeded
            Answer::GiveUp
        } else {
            // Look at how much time has elapsed since the last attempt
            let elapsed = now - self.last_attempt;
            if self.retry_interval > elapsed {
                // Wait a bit
                Answer::WaitFor(self.retry_interval - elapsed)
            } else {
                info!("Retry retriggered by policy");
                Answer::Retry
            }
        }
    }
}

#[test]
fn session_retry() {
    let mut session_retry = SessionRetryPolicy::default();

    let now = Utc::now();

    let retry_interval = Duration::milliseconds(SessionRetryPolicy::DEFAULT_RETRY_INTERVAL_MS);
    let last_attempt_expired = now - retry_interval - Duration::nanoseconds(1);
    let last_attempt_wait = now - retry_interval + Duration::seconds(1);

    session_retry.set_last_attempt(last_attempt_expired);
    assert_eq!(session_retry.should_retry_connect(now), Answer::Retry);
    session_retry.retry_count = SessionRetryPolicy::DEFAULT_RETRY_LIMIT - 1;
    assert_eq!(session_retry.should_retry_connect(now), Answer::Retry);
    session_retry.retry_count = SessionRetryPolicy::DEFAULT_RETRY_LIMIT;
    assert_eq!(session_retry.should_retry_connect(now), Answer::GiveUp);

    session_retry.set_last_attempt(last_attempt_wait);
    session_retry.retry_count = 0;
    assert_eq!(session_retry.should_retry_connect(now), Answer::WaitFor(Duration::seconds(1)));
}