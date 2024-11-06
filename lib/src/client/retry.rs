use tokio::time::Duration;

pub(crate) struct ExponentialBackoff {
    max_sleep: Duration,
    max_retries: Option<u32>,
    current_sleep: Duration,
    retry_count: u32,
}

impl ExponentialBackoff {
    pub fn new(max_sleep: Duration, max_retries: Option<u32>, initial_sleep: Duration) -> Self {
        Self {
            max_sleep,
            max_retries,
            current_sleep: initial_sleep,
            retry_count: 0,
        }
    }
}

impl Iterator for ExponentialBackoff {
    type Item = Duration;

    fn next(&mut self) -> Option<Self::Item> {
        if self.max_retries.is_some_and(|max| max <= self.retry_count) {
            return None;
        }

        let next_sleep = self.current_sleep;
        self.current_sleep = self.max_sleep.min(self.current_sleep * 2);
        self.retry_count += 1;

        Some(next_sleep)
    }
}

#[derive(Debug, Clone)]
pub struct SessionRetryPolicy {
    reconnect_max_sleep: Duration,
    reconnect_retry_limit: Option<u32>,
    reconnect_initial_sleep: Duration,
}

impl Default for SessionRetryPolicy {
    fn default() -> Self {
        Self {
            reconnect_max_sleep: Duration::from_millis(Self::DEFAULT_MAX_SLEEP_MS),
            reconnect_retry_limit: Some(Self::DEFAULT_RETRY_LIMIT),
            reconnect_initial_sleep: Duration::from_millis(Self::DEFAULT_INITIAL_SLEEP_MS),
        }
    }
}

impl SessionRetryPolicy {
    pub const DEFAULT_RETRY_LIMIT: u32 = 10;
    pub const DEFAULT_INITIAL_SLEEP_MS: u64 = 500;
    pub const DEFAULT_MAX_SLEEP_MS: u64 = 30000;

    pub fn new(max_sleep: Duration, retry_limit: Option<u32>, initial_sleep: Duration) -> Self {
        Self {
            reconnect_max_sleep: max_sleep,
            reconnect_retry_limit: retry_limit,
            reconnect_initial_sleep: initial_sleep,
        }
    }

    pub(crate) fn new_backoff(&self) -> ExponentialBackoff {
        ExponentialBackoff::new(
            self.reconnect_max_sleep,
            self.reconnect_retry_limit,
            self.reconnect_initial_sleep,
        )
    }

    pub fn infinity(max_sleep: Duration, initial_sleep: Duration) -> Self {
        Self {
            reconnect_initial_sleep: initial_sleep,
            reconnect_retry_limit: None,
            reconnect_max_sleep: max_sleep,
        }
    }

    pub fn never() -> Self {
        Self {
            reconnect_retry_limit: Some(0),
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::SessionRetryPolicy;

    #[test]
    fn session_retry() {
        let policy = SessionRetryPolicy::default();

        let mut backoff = policy.new_backoff();

        assert_eq!(Some(Duration::from_millis(500)), backoff.next());
        assert_eq!(Some(Duration::from_millis(1000)), backoff.next());
        assert_eq!(Some(Duration::from_millis(2000)), backoff.next());
        assert_eq!(Some(Duration::from_millis(4000)), backoff.next());
        assert_eq!(Some(Duration::from_millis(8000)), backoff.next());
        assert_eq!(Some(Duration::from_millis(16000)), backoff.next());
        assert_eq!(Some(Duration::from_millis(30000)), backoff.next());
        assert_eq!(Some(Duration::from_millis(30000)), backoff.next());
        assert_eq!(Some(Duration::from_millis(30000)), backoff.next());
        assert_eq!(Some(Duration::from_millis(30000)), backoff.next());
        assert_eq!(None, backoff.next());
        assert_eq!(None, backoff.next());
    }

    #[test]
    fn session_retry_infinity() {
        let policy =
            SessionRetryPolicy::infinity(Duration::from_millis(3000), Duration::from_millis(500));

        let mut backoff = policy.new_backoff();

        for _ in 0..100 {
            assert!(backoff.next().is_some());
        }

        assert_eq!(Some(Duration::from_millis(3000)), backoff.next());
    }

    #[test]
    fn session_retry_never() {
        let policy = SessionRetryPolicy::never();
        let mut backoff = policy.new_backoff();
        assert!(backoff.next().is_none());
    }
}
