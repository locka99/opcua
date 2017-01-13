use std::io::{Read, Write, Result};

use types::*;
use super::types::*;

#[derive(Debug, Clone, PartialEq)]
pub struct GetEndpointsRequest {
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

impl MessageInfo for GetEndpointsRequest {
    fn object_id(&self) -> ObjectId {
        ObjectId::GetEndpointsRequest_Encoding_DefaultBinary
    }
}

impl BinaryEncoder<GetEndpointsRequest> for GetEndpointsRequest {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += self.request_header.byte_len();
        size += self.endpoint_url.byte_len();
        size += byte_len_array(&self.locale_ids);
        size += byte_len_array(&self.profile_uris);
        size
    }

    fn encode<S: Write>(&self, stream: &mut S) -> Result<usize> {
        let mut size = 0;
        size += self.request_header.encode(stream)?;
        size += self.endpoint_url.encode(stream)?;
        size += write_array(stream, &self.locale_ids)?;
        size += write_array(stream, &self.profile_uris)?;
        Ok(size)
    }

    fn decode<S: Read>(stream: &mut S) -> Result<GetEndpointsRequest> {
        let request_header = RequestHeader::decode(stream)?;
        let endpoint_url = UAString::decode(stream)?;
        let locale_ids: Option<Vec<UAString>> = read_array(stream)?;
        let profile_uris: Option<Vec<UAString>> = read_array(stream)?;
        Ok(GetEndpointsRequest {
            request_header: request_header,
            endpoint_url: endpoint_url,
            locale_ids: locale_ids,
            profile_uris: profile_uris,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct GetEndpointsResponse {
    /// Common response parameters.
    /// The ResponseHeader type is defined in 7.29.
    pub response_header: ResponseHeader,
    /// List of Endpoints that meet criteria specified in the request.
    /// This list is empty if no Endpoints meet the criteria.
    /// The EndpointDescription type is defined in 7.10.
    pub endpoints: Option<Vec<EndpointDescription>>,
}

impl MessageInfo for GetEndpointsResponse {
    fn object_id(&self) -> ObjectId {
        ObjectId::GetEndpointsResponse_Encoding_DefaultBinary
    }
}

impl BinaryEncoder<GetEndpointsResponse> for GetEndpointsResponse {
    fn byte_len(&self) -> usize {
        let mut size = self.response_header.byte_len();
        size += byte_len_array(&self.endpoints);
        size
    }

    fn encode<S: Write>(&self, stream: &mut S) -> Result<usize> {
        let mut size = 0;
        size += self.response_header.encode(stream)?;
        size += write_array(stream, &self.endpoints)?;
        Ok(size)
    }

    fn decode<S: Read>(stream: &mut S) -> Result<GetEndpointsResponse> {
        let response_header = ResponseHeader::decode(stream)?;
        let endpoints: Option<Vec<EndpointDescription>> = read_array(stream)?;
        Ok(GetEndpointsResponse {
            response_header: response_header,
            endpoints: endpoints,
        })
    }
}
