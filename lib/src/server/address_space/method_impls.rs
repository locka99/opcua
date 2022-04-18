// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

use std::sync::Arc;

use crate::sync::*;
use crate::types::{
    service_types::{CallMethodRequest, CallMethodResult},
    status_code::StatusCode,
    *,
};

use crate::server::{callbacks::Method, session::SessionManager};

/// Count the number of provided input arguments, comparing them to the expected number.
fn ensure_input_argument_count(
    request: &CallMethodRequest,
    expected: usize,
) -> Result<(), StatusCode> {
    if let Some(ref input_arguments) = request.input_arguments {
        let actual = input_arguments.len();
        if actual == expected {
            Ok(())
        } else if actual < expected {
            debug!("Method call fails BadArgumentsMissing");
            Err(StatusCode::BadArgumentsMissing)
        } else {
            debug!("Method call fails BadTooManyArguments");
            Err(StatusCode::BadTooManyArguments)
        }
    } else if expected == 0 {
        Ok(())
    } else {
        debug!("Method call fails BadArgumentsMissing");
        Err(StatusCode::BadArgumentsMissing)
    }
}

/// Gets the input argument value, expecting it to the specified variant type. If it fails,
/// it returns an error
macro_rules! get_input_argument {
    ( $request:expr, $index: expr, $variant_type: ident ) => {{
        let input_arguments = $request.input_arguments.as_ref().unwrap();
        let arg = input_arguments.get($index).unwrap();
        if let Variant::$variant_type(value) = arg {
            Ok(value)
        } else {
            // Argument is not the expected type
            Err(StatusCode::BadInvalidArgument)
        }
    }};
}

/// Search all sessions in the session map except the specified one for a matching subscription id
fn subscription_exists_on_other_session(
    this_session_id: &NodeId,
    session_manager: Arc<RwLock<SessionManager>>,
    subscription_id: u32,
) -> bool {
    // Check if the subscription exists on another session
    let session_manager = trace_read_lock!(session_manager);
    session_manager.sessions.iter().any(|(_, s)| {
        let s = trace_read_lock!(s);
        s.session_id() != this_session_id && s.subscriptions().contains(subscription_id)
    })
}

/// This is the handler for Server.ResendData method call.
pub struct ServerResendDataMethod;

impl Method for ServerResendDataMethod {
    fn call(
        &mut self,
        session_id: &NodeId,
        session_manager: Arc<RwLock<SessionManager>>,
        request: &CallMethodRequest,
    ) -> Result<CallMethodResult, StatusCode> {
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

        {
            let session_manager = trace_read_lock!(session_manager);
            if let Some(session) = session_manager.find_session_by_id(session_id) {
                let mut session = trace_write_lock!(session);
                if let Some(subscription) = session.subscriptions_mut().get_mut(*subscription_id) {
                    subscription.set_resend_data();
                    return Ok(CallMethodResult {
                        status_code: StatusCode::Good,
                        input_argument_results: Some(vec![StatusCode::Good]),
                        input_argument_diagnostic_infos: None,
                        output_arguments: None,
                    });
                };
            } else {
                return Err(StatusCode::BadSessionIdInvalid);
            }
        }

        if subscription_exists_on_other_session(session_id, session_manager, *subscription_id) {
            Err(StatusCode::BadUserAccessDenied)
        } else {
            Err(StatusCode::BadSubscriptionIdInvalid)
        }
    }
}

/// This is the handler for the Server.GetMonitoredItems method call.
pub struct ServerGetMonitoredItemsMethod;

impl Method for ServerGetMonitoredItemsMethod {
    fn call(
        &mut self,
        session_id: &NodeId,
        session_manager: Arc<RwLock<SessionManager>>,
        request: &CallMethodRequest,
    ) -> Result<CallMethodResult, StatusCode> {
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

        // Check for subscription on the session supplied
        {
            let session_manager = trace_read_lock!(session_manager);
            if let Some(session) = session_manager.find_session_by_id(session_id) {
                let session = trace_read_lock!(session);
                if let Some(subscription) =
                    session.subscriptions().subscriptions().get(subscription_id)
                {
                    // Response
                    //   serverHandles: Vec<u32>
                    //   clientHandles: Vec<u32>
                    let (server_handles, client_handles) = subscription.get_handles();

                    let server_handles = Variant::from(server_handles);
                    let client_handles = Variant::from(client_handles);
                    let output_arguments = vec![server_handles, client_handles];

                    return Ok(CallMethodResult {
                        status_code: StatusCode::Good,
                        input_argument_results: Some(vec![StatusCode::Good]),
                        input_argument_diagnostic_infos: None,
                        output_arguments: Some(output_arguments),
                    });
                };
            } else {
                return Err(StatusCode::BadSessionIdInvalid);
            }
        }
        if subscription_exists_on_other_session(session_id, session_manager, *subscription_id) {
            debug!("Method handler for GetMonitoredItems returns BadUserAccessDenied");
            Err(StatusCode::BadUserAccessDenied)
        } else {
            debug!("Method handler for GetMonitoredItems returns BadSubscriptionIdInvalid");
            Err(StatusCode::BadSubscriptionIdInvalid)
        }
    }
}
