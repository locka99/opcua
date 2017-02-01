use types::NodeId;

mod node_ids;
mod status_codes;

macro_rules! use_generated_types {
    [ $( $x:ident ), * ] => {
        $(
        mod $x;
        pub use self::$x::*;
        )*
    }
}

use_generated_types! [
    application_description,
    channel_security_token,
    open_secure_channel_request,
    open_secure_channel_response,
    close_secure_channel_request,
    close_secure_channel_response,
    create_session_request,
    create_session_response,
    close_session_request,
    close_session_response,
    activate_session_request,
    activate_session_response,
    get_endpoints_request,
    get_endpoints_response,
    endpoint_description,
    browse_request,
    browse_response,
    browse_result,
    browse_description,
    view_description,
    reference_description,
    create_subscription_request,
    create_subscription_response,
    publish_request,
    publish_response,
    subscription_acknowledgement,
    notification_message,
    read_request,
    read_response,
    read_value_id,
    create_monitored_items_request,
    create_monitored_items_response,
    monitored_item_create_request,
    monitored_item_create_result,
    monitoring_parameters,
    user_token_policy,
    signature_data,
    signed_software_certificate,
    anonymous_identity_token,
    user_name_identity_token
];

pub use self::node_ids::*;

impl ObjectId {
    pub fn as_node_id(&self) -> NodeId {
        NodeId::from_object_id(*self)
    }
}

impl ObjectTypeId {
    pub fn as_node_id(&self) -> NodeId {
        NodeId::from_object_type_id(*self)
    }
}

pub use self::status_codes::*;
