use opcua_types::*;
use opcua_types::status_code::StatusCode;
use opcua_types::service_types::{CallMethodRequest, CallMethodResult};

use crate::{
    address_space::AddressSpace,
    state::ServerState,
    session::Session
};

/// Count the number of provided input arguments, comparing them to the expected number.
fn ensure_input_argument_count(request: &CallMethodRequest, expected: usize) -> Result<(), StatusCode> {
    if let Some(ref input_arguments) = request.input_arguments {
        let actual = input_arguments.len();
        if actual == expected {
            Ok(())
        } else if actual < expected {
            Err(StatusCode::BadArgumentsMissing)
        } else {
            Err(StatusCode::BadTooManyArguments)
        }
    } else {
        if expected == 0 {
            Ok(())
        } else {
            Err(StatusCode::BadArgumentsMissing)
        }
    }
}

/// Gets the input argument value, expecting it to the specified variant type. If it fails,
/// it returns an error
macro_rules! get_input_argument {
    ( $request:expr, $index: expr, $variant_type: ident ) => {
        {
            let input_arguments = $request.input_arguments.as_ref().unwrap();
            let arg = input_arguments.get($index).unwrap();
            if let Variant::$variant_type(value) = arg {
                Ok(value)
            }
            else {
                // Argument is not the expected type
                Err(StatusCode::BadInvalidArgument)
            }
        }
    }
}

/// This is the handler for Server.ResendData method call.
pub fn handle_resend_data(_: &AddressSpace, _: &ServerState, session: &mut Session, request: &CallMethodRequest) -> Result<CallMethodResult, StatusCode> {
    debug!("Method handler for ResendData");

    // OPC UA part 5 - ResendData([in] UInt32 subscriptionId);
    //
    // subscriptionId - Identifier of the subscription to refresh
    //
    // Return codes
    //
    // BadSubscriptionIdInvalid
    // BadUserAccessDenied

    ensure_input_argument_count(request, 1)?;

    let subscription_id = get_input_argument!(request, 0, UInt32)?;

    if let Some(subscription) = session.subscriptions.get_mut(*subscription_id) {
        subscription.set_resend_data();
        Ok(CallMethodResult {
            status_code: StatusCode::Good,
            input_argument_results: Some(vec![StatusCode::Good]),
            input_argument_diagnostic_infos: None,
            output_arguments: None,
        })
    } else {
        // Subscription id does not exist
        // Note we could check other sessions for a matching id and return BadUserAccessDenied in that case
        Err(StatusCode::BadSubscriptionIdInvalid)
    }
}

/// This is the handler for the Server.GetMonitoredItems method call.
pub fn handle_get_monitored_items(_: &AddressSpace, _: &ServerState, session: &mut Session, request: &CallMethodRequest) -> Result<CallMethodResult, StatusCode> {
    debug!("Method handler for GetMonitoredItems");

    // OPC UA part 5 - GetMonitoredItems([in] UInt32 subscriptionId, [out] UInt32[] serverHandles, [out] UInt32[] clientHandles);
    //
    // subscriptionId - Identifier of the subscription
    // serverHandles - Array of serverHandles for all MonitoredItems of the Subscription identified by subscriptionId
    // clientHandles - Array of clientHandles for all MonitoredItems of the Subscription identified by subscriptionId
    //
    // Return codes
    //
    // BadSubscriptionIdInvalid
    // BadUserAccessDenied

    ensure_input_argument_count(request, 1)?;

    let subscription_id = get_input_argument!(request, 0, UInt32)?;

    if let Some(subscription) = session.subscriptions.subscriptions().get(&subscription_id) {
        // Response
        //   serverHandles: Vec<u32>
        //   clientHandles: Vec<u32>
        let (server_handles, client_handles) = subscription.get_handles();
        Ok(CallMethodResult {
            status_code: StatusCode::Good,
            input_argument_results: Some(vec![StatusCode::Good]),
            input_argument_diagnostic_infos: None,
            output_arguments: Some(vec![server_handles.into(), client_handles.into()]),
        })
    } else {
        // Subscription id does not exist
        // Note we could check other sessions for a matching id and return BadUserAccessDenied in that case
        Err(StatusCode::BadSubscriptionIdInvalid)
    }
}
