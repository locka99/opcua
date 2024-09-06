macro_rules! take_service_items {
    ($request:ident, $items:expr, $limit:expr) => {{
        let Some(it) = $items else {
            return service_fault!($request, StatusCode::BadNothingToDo);
        };
        if it.is_empty() {
            return service_fault!($request, StatusCode::BadNothingToDo);
        }
        if it.len() > $limit {
            return service_fault!($request, StatusCode::BadTooManyOperations);
        }
        it
    }};
}

mod attribute;
mod method;
mod monitored_items;
mod node_management;
mod query;
mod subscriptions;
mod view;

pub(super) use attribute::*;
pub(super) use method::*;
pub(super) use monitored_items::*;
pub(super) use node_management::*;
pub(super) use query::*;
pub(super) use subscriptions::*;
pub(super) use view::*;
