use types::*;
use super::types::*;


impl MessageInfo for GetEndpointsRequest {
    fn object_id(&self) -> ObjectId {
        ObjectId::GetEndpointsRequest_Encoding_DefaultBinary
    }
}

impl MessageInfo for GetEndpointsResponse {
    fn object_id(&self) -> ObjectId {
        ObjectId::GetEndpointsResponse_Encoding_DefaultBinary
    }
}
