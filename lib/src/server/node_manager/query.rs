use crate::{
    crypto::random,
    server::{
        session::{
            continuation_points::{ContinuationPoint, EmptyContinuationPoint},
            instance::Session,
        },
        ParsedContentFilter,
    },
    types::{
        AttributeId, ByteString, ExpandedNodeId, NodeTypeDescription, NumericRange, ParsingResult,
        QueryDataDescription, QueryDataSet, RelativePath, StatusCode,
    },
};

pub(crate) struct QueryContinuationPoint {
    pub node_manager_index: usize,
    pub continuation_point: ContinuationPoint,
    pub id: ByteString,

    node_types: Vec<ParsedNodeTypeDescription>,
    filter: ParsedContentFilter,
    max_data_sets_to_return: usize,
    max_references_to_return: usize,
}

#[derive(Debug)]
/// Parsed and validated version of the OPC-UA `QueryDataDescription`.
pub struct ParsedQueryDataDescription {
    /// The relative path to the node being referenced.
    pub relative_path: RelativePath,
    /// Attribute ID of the attribute being referenced.
    pub attribute_id: AttributeId,
    /// Index range for the read.
    pub index_range: NumericRange,
}

impl ParsedQueryDataDescription {
    pub(crate) fn parse(desc: QueryDataDescription) -> Result<Self, StatusCode> {
        let attribute_id = AttributeId::from_u32(desc.attribute_id)
            .map_err(|_| StatusCode::BadAttributeIdInvalid)?;
        let index_range = desc
            .index_range
            .as_ref()
            .parse::<NumericRange>()
            .map_err(|_| StatusCode::BadIndexRangeInvalid)?;

        Ok(Self {
            relative_path: desc.relative_path,
            attribute_id,
            index_range,
        })
    }
}

#[derive(Debug)]
/// Parsed and validated version of the OPC-UA `NodeTypeDescription`.
pub struct ParsedNodeTypeDescription {
    /// Type definition to query.
    pub type_definition_node: ExpandedNodeId,
    /// Whether to include sub types of the type definition.
    pub include_sub_types: bool,
    /// List of values to return.
    pub data_to_return: Vec<ParsedQueryDataDescription>,
}

impl ParsedNodeTypeDescription {
    pub(crate) fn parse(desc: NodeTypeDescription) -> (ParsingResult, Result<Self, StatusCode>) {
        let num_descs = desc
            .data_to_return
            .as_ref()
            .map(|d| d.len())
            .unwrap_or_default();
        let mut desc_results = Vec::with_capacity(num_descs);
        let mut final_descs = Vec::with_capacity(num_descs);
        for child in desc.data_to_return.into_iter().flatten() {
            match ParsedQueryDataDescription::parse(child) {
                Ok(c) => {
                    desc_results.push(StatusCode::Good);
                    final_descs.push(c);
                }
                Err(e) => desc_results.push(e),
            }
        }

        if final_descs.len() < num_descs {
            return (
                ParsingResult {
                    status_code: StatusCode::BadInvalidArgument,
                    data_status_codes: Some(desc_results),
                    data_diagnostic_infos: None,
                },
                Err(StatusCode::BadInvalidArgument),
            );
        }

        (
            ParsingResult {
                status_code: StatusCode::Good,
                data_diagnostic_infos: None,
                data_status_codes: None,
            },
            Ok(ParsedNodeTypeDescription {
                type_definition_node: desc.type_definition_node,
                include_sub_types: desc.include_sub_types,
                data_to_return: final_descs,
            }),
        )
    }
}

/// Container for a `Query` service call.
pub struct QueryRequest {
    node_types: Vec<ParsedNodeTypeDescription>,
    filter: ParsedContentFilter,
    max_data_sets_to_return: usize,
    max_references_to_return: usize,
    continuation_point: Option<ContinuationPoint>,
    next_continuation_point: Option<ContinuationPoint>,
    status: StatusCode,
    node_manager_index: usize,

    data_sets: Vec<QueryDataSet>,
}

impl QueryRequest {
    pub(crate) fn new(
        node_types: Vec<ParsedNodeTypeDescription>,
        filter: ParsedContentFilter,
        max_data_sets_to_return: usize,
        max_references_to_return: usize,
    ) -> Self {
        Self {
            node_types,
            filter,
            max_data_sets_to_return,
            max_references_to_return,
            continuation_point: None,
            next_continuation_point: None,
            data_sets: Vec::new(),
            status: StatusCode::Good,
            node_manager_index: 0,
        }
    }

    pub(crate) fn from_continuation_point(point: QueryContinuationPoint) -> Self {
        Self {
            node_types: point.node_types,
            filter: point.filter,
            max_data_sets_to_return: point.max_data_sets_to_return,
            max_references_to_return: point.max_references_to_return,
            continuation_point: Some(point.continuation_point),
            next_continuation_point: None,
            status: StatusCode::Good,
            data_sets: Vec::new(),
            node_manager_index: point.node_manager_index,
        }
    }

    /// Data sets to query.
    pub fn data_sets(&self) -> &[QueryDataSet] {
        &self.data_sets
    }

    /// Continuation point, if present.
    pub fn continuation_point(&self) -> Option<&ContinuationPoint> {
        self.continuation_point.as_ref()
    }

    /// Maximum number of references to return.
    pub fn max_references_to_return(&self) -> usize {
        self.max_references_to_return
    }

    /// Maximum number of data sets to return.
    pub fn max_data_sets_to_return(&self) -> usize {
        self.max_data_sets_to_return
    }

    /// Content filter that the results must match.
    pub fn filter(&self) -> &ParsedContentFilter {
        &self.filter
    }

    /// Node types to query.
    pub fn node_types(&self) -> &[ParsedNodeTypeDescription] {
        &self.node_types
    }

    /// Space for data sets left.
    pub fn remaining_data_sets(&self) -> usize {
        if self.data_sets.len() >= self.max_data_sets_to_return {
            0
        } else {
            self.max_data_sets_to_return - self.data_sets.len()
        }
    }

    /// Whether this query is completed.
    pub fn is_completed(&self) -> bool {
        self.remaining_data_sets() == 0 || self.next_continuation_point.is_some()
    }

    pub(crate) fn into_result(
        self,
        node_manager_index: usize,
        node_manager_count: usize,
        session: &mut Session,
    ) -> (Vec<QueryDataSet>, ByteString, StatusCode) {
        // If the status is bad, assume the results are suspect and return nothing.
        if self.status.is_bad() {
            return (Vec::new(), ByteString::null(), self.status);
        }
        // There may be a continuation point defined for the current node manager,
        // in that case return that. There is also a corner case here where
        // remaining == 0 and there is no continuation point.
        // In this case we need to pass an empty continuation point
        // to the next node manager.
        let inner = self
            .next_continuation_point
            .map(|c| (c, node_manager_index))
            .or_else(|| {
                if node_manager_index < node_manager_count - 1 {
                    Some((
                        ContinuationPoint::new(Box::new(EmptyContinuationPoint)),
                        node_manager_index + 1,
                    ))
                } else {
                    None
                }
            });

        let continuation_point = inner.map(|(p, node_manager_index)| QueryContinuationPoint {
            node_manager_index,
            continuation_point: p,
            id: random::byte_string(6),
            node_types: self.node_types,
            filter: self.filter,
            max_data_sets_to_return: self.max_data_sets_to_return,
            max_references_to_return: self.max_references_to_return,
        });

        let mut status = self.status;
        let mut cp_id = continuation_point
            .as_ref()
            .map(|c| c.id.clone())
            .unwrap_or_default();

        // If we're out of continuation points, the correct response is to not store it, and
        // set the status code to BadNoContinuationPoints.
        if let Some(c) = continuation_point {
            if session.add_query_continuation_point(&cp_id, c).is_err() {
                status = StatusCode::BadNoContinuationPoints;
                cp_id = ByteString::null();
            }
        }

        (self.data_sets, cp_id, status)
    }

    /// Current result status code.
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// Set the general result of this query.
    pub fn set_status(&mut self, status: StatusCode) {
        self.status = status;
    }

    /// Set the next continuation point for this query.
    pub fn set_next_continuation_point(
        &mut self,
        next_continuation_point: Option<ContinuationPoint>,
    ) {
        self.next_continuation_point = next_continuation_point;
    }

    pub(crate) fn node_manager_index(&self) -> usize {
        self.node_manager_index
    }
}
