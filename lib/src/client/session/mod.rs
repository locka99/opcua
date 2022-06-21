pub mod services;
pub mod session;
pub mod session_state;

macro_rules! session_warn {
    ($session: expr, $($arg:tt)*) =>  {
        warn!("{} {}", $session.session_id(), format!($($arg)*));
    }
}
pub(crate) use session_warn;

macro_rules! session_error {
    ($session: expr, $($arg:tt)*) =>  {
        error!("{} {}", $session.session_id(), format!($($arg)*));
    }
}
pub(crate) use session_error;

macro_rules! session_debug {
    ($session: expr, $($arg:tt)*) =>  {
        debug!("{} {}", $session.session_id(), format!($($arg)*));
    }
}
pub(crate) use session_debug;

macro_rules! session_trace {
    ($session: expr, $($arg:tt)*) =>  {
        trace!("{} {}", $session.session_id(), format!($($arg)*));
    }
}
pub(crate) use session_trace;
