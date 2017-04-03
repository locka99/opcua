mod node_ids;
mod status_codes;

macro_rules! use_generated_types {
    [ $( $x:ident, ) * ] => (use_generated_types![ $( $x ),* ];);
    [ $( $x:ident ), * ] => {
        $(
        mod $x;
        pub use self::$x::*;
        )*
    }
}

use_generated_types![
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
    browse_next_request,
    browse_next_response,
    view_description,
    reference_description,
    create_subscription_request,
    create_subscription_response,
    modify_subscription_request,
    modify_subscription_response,
    delete_subscriptions_request,
    delete_subscriptions_response,
    set_publishing_mode_request,
    set_publishing_mode_response,
    publish_request,
    publish_response,
    republish_request,
    republish_response,
    subscription_acknowledgement,
    notification_message,
    read_request,
    read_response,
    read_value_id,
    write_request,
    write_response,
    write_value,
    create_monitored_items_request,
    create_monitored_items_response,
    monitored_item_create_request,
    monitored_item_create_result,
    monitoring_parameters,
    delete_monitored_items_request,
    delete_monitored_items_response,
    modify_monitored_items_request,
    modify_monitored_items_response,
    monitored_item_modify_request,
    monitored_item_modify_result,
    monitored_item_notification,
    data_change_filter,
    data_change_notification,
    monitoring_filter,
    monitoring_filter_result,
    event_filter,
    event_filter_result,
    aggregate_filter,
    aggregate_filter_result,
    aggregate_configuration,
    simple_attribute_operand,
    content_filter,
    content_filter_element,
    content_filter_element_result,
    content_filter_result,
    user_token_policy,
    signature_data,
    signed_software_certificate,
    anonymous_identity_token,
    user_name_identity_token,
];

pub use self::node_ids::*;

pub use self::status_codes::*;
