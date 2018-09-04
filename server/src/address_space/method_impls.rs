use opcua_types::*;
use opcua_types::status_code::StatusCode;
use opcua_types::status_code::StatusCode::*;
use opcua_types::service_types::{CallMethodRequest, CallMethodResult};

use address_space::AddressSpace;
use state::ServerState;
use session::Session;

/// This is the handler for the GetMonitoredItems method call. It's called via a CallRequest on
/// the Method service.
pub fn handle_get_monitored_items(_: &AddressSpace, _: &ServerState, session: &Session, request: &CallMethodRequest) -> Result<CallMethodResult, StatusCode> {
    debug!("Method handler for GetMonitoredItems");
    // Expect arguments:
    //   subscriptionId: UInt32
    if let Some(ref input_arguments) = request.input_arguments {
        match input_arguments.len() {
            1 => {
                let arg1 = input_arguments.get(0).unwrap();
                if let Variant::UInt32(subscription_id) = arg1 {
                    if let Some(subscription) = session.subscriptions.subscriptions().get(&subscription_id) {
                        // Response
                        //   serverHandles: Vec<UInt32>
                        //   clientHandles: Vec<UInt32>
                        let (server_handles, client_handles) = subscription.get_handles();
                        Ok(CallMethodResult {
                            status_code: Good,
                            input_argument_results: Some(vec![Good]),
                            input_argument_diagnostic_infos: None,
                            output_arguments: Some(vec![server_handles.into(), client_handles.into()]),
                        })
                    } else {
                        // Subscription id does not exist
                        // Note we could check other sessions for a matching id and return BadUserAccessDenied in that case
                        Err(BadSubscriptionIdInvalid)
                    }
                } else {
                    // Argument is not the right type
                    Err(BadInvalidArgument)
                }
            }
            0 => Err(BadArgumentsMissing),
            _ => Err(BadTooManyArguments),
        }
    } else {
        // Args are missing
        Err(BadArgumentsMissing)
    }
}
