use std::any::Any;

/// Representation of a dynamic continuation point.
/// Each node manager may provide their own continuation point type,
/// which is stored by the server. This wraps that value and provides interfaces
/// to access it for a given node manager.
pub struct ContinuationPoint {
    payload: Box<dyn Any + Send + Sync + 'static>,
}

impl ContinuationPoint {
    pub fn new<T: Send + Sync + 'static>(item: Box<T>) -> Self {
        Self { payload: item }
    }

    /// Retrieve the value of the continuation point.
    /// This will return `None` if the stored value is not equal to the
    /// given type. Most node managers should report an error if this happens.
    pub fn get<T: Send + Sync + 'static>(&self) -> Option<&T> {
        self.payload.downcast_ref()
    }

    /// Retrieve the value of the continuation point.
    /// This will return `None` if the stored value is not equal to the
    /// given type. Most node managers should report an error if this happens.
    pub fn get_mut<T: Send + Sync + 'static>(&mut self) -> Option<&mut T> {
        self.payload.downcast_mut()
    }

    pub fn take<T: Send + Sync + 'static>(self) -> Option<Box<T>> {
        self.payload.downcast().ok()
    }
}

/// Continuation point implementation used when continuation is necessary, but
/// the last called node manager is empty.
pub(crate) struct EmptyContinuationPoint;
