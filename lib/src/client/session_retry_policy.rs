// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

use chrono::Duration;

use crate::types::date_time::DateTime;

#[derive(PartialEq, Debug)]
pub enum Answer {
    /// Retry immediately
    Retry,
    /// Wait for this many milliseconds
    WaitFor(u32),
    /// Give up reconnecting
    GiveUp,
}

/// The session retry policy determines what to if the connection fails. In these circumstances,
/// the client needs to re-establish a connection and the policy says how many times to try between
/// failure and at what interval.
///
/// The retry policy may choose a `retry_limit` of `None` for infinite retries. It may define
/// a `retry_interval` for the period of time in MS between each retry. Note that the policy retains
/// its own minimum retry interval and will not retry any faster than that.
///
/// Once a connection succeeds, the retry limit is reset.
#[derive(Debug, PartialEq, Clone)]
pub struct SessionRetryPolicy {
    /// The session timeout period in milliseconds. Used by client to run a keep-alive operation. Initially this
    /// will contain your desired timeout period, but it will be adjusted when the session is created.
    session_timeout: f64,
    /// The maximum number of times to retry between failures before giving up. A value of 0 means
    /// no retries, i.e. give up on first fail, None means no limit, i.e. infinity
    retry_limit: Option<u32>,
    /// Interval between retries in milliseconds
    retry_interval: u32,
    /// The number of failed attempts so far since the last connection. When the connection succeeds
    /// this value is reset.
    retry_count: u32,
    /// The last retry attempt timestamp.
    last_attempt: DateTime,
}

impl Default for SessionRetryPolicy {
    fn default() -> Self {
        Self::new(
            Self::DEFAULT_SESSION_TIMEOUT_MS,
            Self::DEFAULT_RETRY_LIMIT,
            Self::DEFAULT_RETRY_INTERVAL_MS,
        )
    }
}

impl SessionRetryPolicy {
    /// The default retry policy will attempt to reconnect up to this many times.
    pub const DEFAULT_RETRY_LIMIT: u32 = 10;
    /// The default retry policy will wait this duration between reconnect attempts.
    pub const DEFAULT_RETRY_INTERVAL_MS: u32 = 10000;
    /// The minimum retry interval
    pub const MIN_RETRY_INTERVAL_MS: u32 = 500;
    /// The default session timeout interval in millis
    pub const DEFAULT_SESSION_TIMEOUT_MS: f64 = std::f64::MAX;

    /// Create a `SessionRetryPolicy` with a limit and interval
    pub fn new(session_timeout: f64, retry_limit: u32, retry_interval: u32) -> Self {
        let session_timeout = if session_timeout == 0.0 {
            Self::DEFAULT_SESSION_TIMEOUT_MS
        } else {
            session_timeout
        };
        let retry_interval = if retry_interval < Self::MIN_RETRY_INTERVAL_MS {
            Self::MIN_RETRY_INTERVAL_MS
        } else {
            retry_interval
        };
        SessionRetryPolicy {
            session_timeout,
            retry_count: 0,
            last_attempt: Self::last_attempt_default(),
            retry_limit: Some(retry_limit),
            retry_interval,
        }
    }

    /// Create a `SessionRetryPolicy` that tries forever at the specified interval
    pub fn infinity(session_timeout: f64, retry_interval: u32) -> Self {
        let session_timeout = if session_timeout == 0.0 {
            Self::DEFAULT_SESSION_TIMEOUT_MS
        } else {
            session_timeout
        };
        let retry_interval = if retry_interval < Self::MIN_RETRY_INTERVAL_MS {
            Self::MIN_RETRY_INTERVAL_MS
        } else {
            retry_interval
        };
        SessionRetryPolicy {
            session_timeout,
            retry_count: 0,
            last_attempt: Self::last_attempt_default(),
            retry_limit: None,
            retry_interval,
        }
    }

    /// Create a `SessionRetryPolicy` that never tries again.
    pub fn never(session_timeout: f64) -> Self {
        Self::new(session_timeout, 0, 0)
    }

    fn last_attempt_default() -> DateTime {
        DateTime::ymd(1900, 1, 1)
    }

    pub fn session_timeout(&self) -> f64 {
        self.session_timeout
    }

    pub fn retry_count(&self) -> u32 {
        self.retry_count
    }

    pub fn increment_retry_count(&mut self) {
        self.retry_count += 1;
    }

    pub fn reset_retry_count(&mut self) {
        self.retry_count = 0;
    }

    pub fn set_last_attempt(&mut self, last_attempt: DateTime) {
        self.last_attempt = last_attempt;
    }

    /// Asks the policy, given the last retry attempt, should we try to connect again, wait a period of time
    /// or give up entirely.
    pub fn should_retry_connect(&self, now: DateTime) -> Answer {
        if let Some(retry_limit) = self.retry_limit {
            if self.retry_count >= retry_limit {
                // Number of retries have been exceeded
                return Answer::GiveUp;
            }
        }

        if self.retry_interval < Self::MIN_RETRY_INTERVAL_MS {
            // The constructors don't allow for this
            panic!("Retry interval is less than the minimum permitted.");
        }

        // Look at how much time has elapsed since the last attempt
        let elapsed = now - self.last_attempt;
        let retry_interval = Duration::milliseconds(self.retry_interval as i64);
        if retry_interval > elapsed {
            // Wait a bit
            Answer::WaitFor((retry_interval - elapsed).num_milliseconds() as u32)
        } else {
            info!("Retry retriggered by policy");
            Answer::Retry
        }
    }
}

#[test]
fn session_retry() {
    let mut session_retry = SessionRetryPolicy::default();

    let now = DateTime::now();

    let retry_interval =
        Duration::milliseconds(SessionRetryPolicy::DEFAULT_RETRY_INTERVAL_MS as i64);
    let last_attempt_expired = now - retry_interval - Duration::nanoseconds(1);
    let last_attempt_wait = now - retry_interval + Duration::seconds(1);

    assert_eq!(
        session_retry.session_timeout(),
        SessionRetryPolicy::DEFAULT_SESSION_TIMEOUT_MS
    );

    session_retry.set_last_attempt(last_attempt_expired);
    assert_eq!(session_retry.should_retry_connect(now), Answer::Retry);
    session_retry.retry_count = SessionRetryPolicy::DEFAULT_RETRY_LIMIT - 1;
    assert_eq!(session_retry.should_retry_connect(now), Answer::Retry);
    session_retry.retry_count = SessionRetryPolicy::DEFAULT_RETRY_LIMIT;
    assert_eq!(session_retry.should_retry_connect(now), Answer::GiveUp);

    session_retry.set_last_attempt(last_attempt_wait);
    session_retry.retry_count = 0;
    assert_eq!(
        session_retry.should_retry_connect(now),
        Answer::WaitFor(1000)
    );
}

#[test]
fn session_retry_infinity() {
    let session_retry = SessionRetryPolicy::infinity(444.444, 1000);
    let now = DateTime::now();
    assert_eq!(session_retry.should_retry_connect(now), Answer::Retry);
    assert_eq!(session_retry.session_timeout(), 444.444);
}

#[test]
fn session_retry_never() {
    let session_retry = SessionRetryPolicy::never(987.123);
    let now = DateTime::now();
    assert_eq!(session_retry.should_retry_connect(now), Answer::GiveUp);
    assert_eq!(session_retry.session_timeout(), 987.123);
}
