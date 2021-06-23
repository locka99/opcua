// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2020 Adam Lock

use std::sync::{Arc, RwLock};

use opcua_types::service_types::{CallMethodRequest, CallMethodResult};
use opcua_types::status_code::StatusCode;
use opcua_types::*;

use crate::{
    callbacks::Method,
    session::{Session, SessionMap},
};

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
            Err(StatusCode::BadArgumentsMissing)
        } else {
            Err(StatusCode::BadTooManyArguments)
        }
    } else if expected == 0 {
        Ok(())
    } else {
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
    session: &mut Session,
    session_map: Arc<RwLock<SessionMap>>,
    subscription_id: u32,
) -> bool {
    // Check if the subscription exists on another session
    let session_map = trace_read_lock_unwrap!(session_map);
    session_map.session_map.iter().any(|(_, s)| {
        let s = trace_read_lock_unwrap!(s);
        s.session_id() != session.session_id() && session.subscriptions().contains(subscription_id)
    })
}

/// This is the handler for Server.ResendData method call.
pub struct ServerResendDataMethod;

impl Method for ServerResendDataMethod {
    fn call(
        &mut self,
        session: &mut Session,
        session_map: Arc<RwLock<SessionMap>>,
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

        if let Some(subscription) = session.subscriptions_mut().get_mut(*subscription_id) {
            subscription.set_resend_data();
            Ok(CallMethodResult {
                status_code: StatusCode::Good,
                input_argument_results: Some(vec![StatusCode::Good]),
                input_argument_diagnostic_infos: None,
                output_arguments: None,
            })
        } else if subscription_exists_on_other_session(session, session_map, *subscription_id) {
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
        session: &mut Session,
        session_map: Arc<RwLock<SessionMap>>,
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

        if let Some(subscription) = session
            .subscriptions()
            .subscriptions()
            .get(&subscription_id)
        {
            // Response
            //   serverHandles: Vec<u32>
            //   clientHandles: Vec<u32>
            let (server_handles, client_handles) = subscription.get_handles();

            let server_handles = Variant::from(server_handles);
            let client_handles = Variant::from(client_handles);
            let output_arguments = vec![server_handles, client_handles];

            Ok(CallMethodResult {
                status_code: StatusCode::Good,
                input_argument_results: Some(vec![StatusCode::Good]),
                input_argument_diagnostic_infos: None,
                output_arguments: Some(output_arguments),
            })
        } else if subscription_exists_on_other_session(session, session_map, *subscription_id) {
            Err(StatusCode::BadUserAccessDenied)
        } else {
            Err(StatusCode::BadSubscriptionIdInvalid)
        }
    }
}
