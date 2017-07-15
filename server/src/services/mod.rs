use opcua_types::{SupportedMessage, RequestHeader, ServiceFault, StatusCode};

pub mod message_handler;

trait Service {
    fn service_fault(&self, request_header: &RequestHeader, service_result: StatusCode) -> SupportedMessage {
        ServiceFault::new_supported_message(request_header, service_result)
    }
}

pub mod attribute;
pub mod discovery;
pub mod monitored_item;
pub mod session;
pub mod subscription;
pub mod view;
