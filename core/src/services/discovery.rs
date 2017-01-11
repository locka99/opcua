use std::io::{Read, Write, Result};

use types::*;
use super::types::*;

pub struct GetEndPointsRequest {
    /// Common request parameters.
    /// The authenticationToken is always omitted. The authenticationToken
    /// shall be ignored if it is provided.
    /// The type RequestHeader is defined in 7.28.
    pub request_header: RequestHeader,
    /// The network address that the Client used to access the Discovery Endpoint.
    /// The Server uses this information for diagnostics and to determine what
    /// URLs to return in the response.
    /// The Server should return a suitable default URL if it does not recognize
    /// the HostName in the URL.
    pub endpoint_url: UAString,
    /// List of locales to use.
    /// Specifies the locale to use when returning human readable strings.
    /// This parameter is described in 5.4.2.2.
    pub locale_ids: Option<Vec<UAString>>,
    /// List of Transport Profile that the returned Endpoints shall support. Part 7
    /// defines URIs for the Transport Profiles.
    /// All Endpoints are returned if the list is empty.
    pub profile_uris: Option<Vec<UAString>>,
}

impl BinaryEncoder<GetEndPointsRequest> for GetEndPointsRequest {
    fn byte_len(&self) -> usize {
        let mut size = self.request_header.byte_len() + self.endpoint_url.byte_len();
        // For locale ids
        size += byte_len_array(&self.locale_ids);
        // For profile_uris
        size += byte_len_array(&self.profile_uris);
        size
    }

    fn encode<S: Write>(&self, stream: &mut S) -> Result<usize> {
        unimplemented!();
    }

    fn decode<S: Read>(stream: &mut S) -> Result<GetEndPointsRequest> {
        unimplemented!();
    }
}

pub struct GetEndPointsResponse {
    /// Common response parameters.
    /// The ResponseHeader type is defined in 7.29.
    pub response_header: ResponseHeader,
    /// List of Endpoints that meet criteria specified in the request.
    /// This list is empty if no Endpoints meet the criteria.
    /// The EndpointDescription type is defined in 7.10.
    pub endpoints: Option<Vec<EndpointDescription>>,
}

impl BinaryEncoder<GetEndPointsResponse> for GetEndPointsResponse {
    fn byte_len(&self) -> usize {
        let mut size = self.response_header.byte_len();
        // For locale ids
        size += 4;
        if let Some(ref endpoints) = self.endpoints {
            for endpoint in endpoints.iter() {
                size += endpoint.byte_len();
            }
        }
        size
    }

    fn encode<S: Write>(&self, stream: &mut S) -> Result<usize> {
        unimplemented!();
    }

    fn decode<S: Read>(stream: &mut S) -> Result<GetEndPointsResponse> {
        unimplemented!();
    }
}
