use std::{any::Any, collections::HashMap};

use crate::server::prelude::ByteString;

/// Representation of a dynamic continuation point.
/// Each node manager may provide their own continuation point type,
/// which is stored by the server. This wraps that value and provides interfaces
/// to access it for a given node manager.
pub struct ContinuationPoint {
    payload: Box<dyn Any + Send + Sync + 'static>,
}

impl ContinuationPoint {
    pub fn new<T: Send + Sync + 'static>(item: T) -> Self {
        Self {
            payload: Box::new(item),
        }
    }

    /// Retrieve the value of the continuation point.
    /// This will return `None` if the stored value is not equal to the
    /// given type. Most node managers should report an error if this happens.
    pub fn get<T: Send + Sync + 'static>(&self) -> Option<&T> {
        self.payload.downcast_ref()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.payload.type_id() == EmptyContinuationPoint.type_id()
    }
}

/// Continuation point implementation used when continuation is necessary, but
/// the last called node manager is empty.
pub(crate) struct EmptyContinuationPoint;
