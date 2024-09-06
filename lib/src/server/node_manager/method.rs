use crate::types::{CallMethodRequest, CallMethodResult, NodeId, StatusCode, Variant};

#[derive(Debug)]
/// Container for a single method call in a `Call` service call.
pub struct MethodCall {
    object_id: NodeId,
    method_id: NodeId,
    arguments: Vec<Variant>,

    status: StatusCode,
    argument_results: Vec<StatusCode>,
    outputs: Vec<Variant>,
}

impl MethodCall {
    pub(crate) fn new(request: CallMethodRequest) -> Self {
        Self {
            object_id: request.object_id,
            method_id: request.method_id,
            arguments: request.input_arguments.unwrap_or_default(),
            status: StatusCode::BadMethodInvalid,
            argument_results: Vec::new(),
            outputs: Vec::new(),
        }
    }

    /// Set the argument results to a list of errors.
    /// This will update the `status` to `BadInvalidArgument`.
    ///
    /// The length of `argument_results` must be equal to the length of `arguments`.
    pub fn set_argument_error(&mut self, argument_results: Vec<StatusCode>) {
        self.argument_results = argument_results;
        self.status = StatusCode::BadInvalidArgument;
    }

    /// Set the result of this method call.
    pub fn set_status(&mut self, status: StatusCode) {
        self.status = status;
    }

    /// Set the outputs of this method call.
    pub fn set_outputs(&mut self, outputs: Vec<Variant>) {
        self.outputs = outputs;
    }

    /// Get the arguments to this method call.
    pub fn arguments(&self) -> &[Variant] {
        &self.arguments
    }

    /// Get the ID of the method to call.
    pub fn method_id(&self) -> &NodeId {
        &self.method_id
    }

    /// Get the ID of the object the method is a part of.
    pub fn object_id(&self) -> &NodeId {
        &self.object_id
    }

    /// Get the current status.
    pub fn status(&self) -> StatusCode {
        self.status
    }

    pub(crate) fn into_result(self) -> CallMethodResult {
        CallMethodResult {
            status_code: self.status,
            input_argument_diagnostic_infos: None,
            input_argument_results: if !self.argument_results.is_empty() {
                Some(self.argument_results)
            } else {
                None
            },
            output_arguments: Some(self.outputs),
        }
    }
}
