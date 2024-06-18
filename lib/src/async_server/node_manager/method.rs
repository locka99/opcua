use crate::server::prelude::{CallMethodRequest, CallMethodResult, NodeId, StatusCode, Variant};

pub struct MethodCall {
    object_id: NodeId,
    method_id: NodeId,
    arguments: Vec<Variant>,

    status: StatusCode,
    argument_results: Vec<StatusCode>,
    outputs: Vec<Variant>,
}

impl MethodCall {
    pub fn new(request: CallMethodRequest) -> Self {
        Self {
            object_id: request.object_id,
            method_id: request.method_id,
            arguments: request.input_arguments.unwrap_or_default(),
            status: StatusCode::BadMethodInvalid,
            argument_results: Vec::new(),
            outputs: Vec::new(),
        }
    }

    pub fn set_argument_error(&mut self, argument_results: Vec<StatusCode>) {
        self.argument_results = argument_results;
        self.status = StatusCode::BadInvalidArgument;
    }

    pub fn set_status(&mut self, status: StatusCode) {
        self.status = status;
    }

    pub fn set_outputs(&mut self, outputs: Vec<Variant>) {
        self.outputs = outputs;
    }

    pub fn arguments(&self) -> &[Variant] {
        &self.arguments
    }

    pub fn method_id(&self) -> &NodeId {
        &self.method_id
    }

    pub fn object_id(&self) -> &NodeId {
        &self.object_id
    }

    pub fn status(&self) -> StatusCode {
        self.status
    }

    pub fn into_result(self) -> CallMethodResult {
        CallMethodResult {
            status_code: self.status,
            input_argument_diagnostic_infos: None,
            input_argument_results: Some(self.argument_results),
            output_arguments: Some(self.outputs),
        }
    }
}
