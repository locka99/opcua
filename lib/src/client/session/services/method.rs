use crate::{
    client::{
        session::{process_unexpected_response, session_debug, session_error},
        Session,
    },
    core::supported_message::SupportedMessage,
    types::{
        CallMethodRequest, CallMethodResult, CallRequest, MethodId, NodeId, ObjectId, StatusCode,
        Variant,
    },
};

impl Session {
    /// Calls a single method on an object on the server by sending a [`CallRequest`] to the server.
    ///
    /// See OPC UA Part 4 - Services 5.11.2 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `methods` - The method to call.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<CallMethodResult>)` - A [`CallMethodResult`] for the Method call.
    /// * `Err(StatusCode)` - Request failed, [Status code](StatusCode) is the reason for failure.
    ///
    pub async fn call(
        &self,
        methods: Vec<CallMethodRequest>,
    ) -> Result<Vec<CallMethodResult>, StatusCode> {
        if methods.is_empty() {
            session_error!(self, "call(), was not supplied with any methods to call");
            return Err(StatusCode::BadNothingToDo);
        }

        session_debug!(self, "call()");
        let cnt = methods.len();
        let request = CallRequest {
            request_header: self.make_request_header(),
            methods_to_call: Some(methods),
        };
        let response = self.send(request).await?;
        if let SupportedMessage::CallResponse(response) = response {
            if let Some(results) = response.results {
                if results.len() != cnt {
                    session_error!(
                        self,
                        "call(), expecting {cnt} results from the call to the server, got {} results",
                        results.len()
                    );
                    Err(StatusCode::BadUnexpectedError)
                } else {
                    Ok(results)
                }
            } else {
                session_error!(
                    self,
                    "call(), expecting a result from the call to the server, got nothing"
                );
                Err(StatusCode::BadUnexpectedError)
            }
        } else {
            Err(process_unexpected_response(response))
        }
    }

    /// Calls a single method on an object on the server by sending a [`CallRequest`] to the server.
    ///
    /// See OPC UA Part 4 - Services 5.11.2 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `method` - The method to call. Note this function takes anything that can be turned into
    ///   a [`CallMethodRequest`] which includes a ([`NodeId`], [`NodeId`], `Option<Vec<Variant>>`) tuple
    ///   which refers to the object id, method id, and input arguments respectively.
    ///
    /// # Returns
    ///
    /// * `Ok(CallMethodResult)` - A [`CallMethodResult`] for the Method call.
    /// * `Err(StatusCode)` - Request failed, [Status code](StatusCode) is the reason for failure.
    ///
    pub async fn call_one(
        &self,
        method: impl Into<CallMethodRequest>,
    ) -> Result<CallMethodResult, StatusCode> {
        Ok(self
            .call(vec![method.into()])
            .await?
            .into_iter()
            .next()
            .unwrap())
    }

    /// Calls GetMonitoredItems via call_method(), putting a sane interface on the input / output.
    ///
    /// # Arguments
    ///
    /// * `subscription_id` - Server allocated identifier for the subscription to return monitored items for.
    ///
    /// # Returns
    ///
    /// * `Ok((Vec<u32>, Vec<u32>))` - Result for call, consisting a list of (monitored_item_id, client_handle)
    /// * `Err(StatusCode)` - Request failed, [Status code](StatusCode) is the reason for failure.
    ///
    pub async fn call_get_monitored_items(
        &self,
        subscription_id: u32,
    ) -> Result<(Vec<u32>, Vec<u32>), StatusCode> {
        let args = Some(vec![Variant::from(subscription_id)]);
        let object_id: NodeId = ObjectId::Server.into();
        let method_id: NodeId = MethodId::Server_GetMonitoredItems.into();
        let request: CallMethodRequest = (object_id, method_id, args).into();
        let response = self.call_one(request).await?;
        if let Some(mut result) = response.output_arguments {
            if result.len() == 2 {
                let server_handles = <Vec<u32>>::try_from(&result.remove(0))
                    .map_err(|_| StatusCode::BadUnexpectedError)?;
                let client_handles = <Vec<u32>>::try_from(&result.remove(0))
                    .map_err(|_| StatusCode::BadUnexpectedError)?;
                Ok((server_handles, client_handles))
            } else {
                error!("Expected a result with 2 args and didn't get it.");
                Err(StatusCode::BadUnexpectedError)
            }
        } else {
            error!("Expected a result and didn't get it.");
            Err(StatusCode::BadUnexpectedError)
        }
    }
}
