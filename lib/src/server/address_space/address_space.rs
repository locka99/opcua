// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

//! Implementation of `AddressSpace`.
use std::collections::HashMap;
use std::sync::Arc;

use chrono::Utc;

use crate::sync::*;
use crate::types::{
    node_ids::VariableId::*,
    service_types::{BrowseDirection, CallMethodRequest, CallMethodResult, NodeClass},
    status_code::StatusCode,
    *,
};

use crate::server::{
    address_space::{
        node::{HasNodeId, NodeType},
        object::{Object, ObjectBuilder},
        references::{Reference, ReferenceDirection, References},
        variable::Variable,
        AttrFnGetter,
    },
    callbacks, constants,
    diagnostics::ServerDiagnostics,
    historical::HistoryServerCapabilities,
    session::SessionManager,
    state::ServerState,
};

/// Finds a node in the address space and coerces it into a reference of the expected node type.
macro_rules! find_node {
    ($a: expr, $id: expr, $node_type: ident) => {
        $a.find_node($id).and_then(|node| match node {
            NodeType::$node_type(ref node) => Some(node.as_ref()),
            _ => None,
        })
    };
}

/// Finds a node in the address space and coerces it into a mutable reference of the expected node type.
macro_rules! find_node_mut {
    ($a: expr, $id: expr, $node_type: ident) => {
        $a.find_node_mut($id).and_then(|node| match node {
            NodeType::$node_type(ref mut node) => Some(node.as_mut()),
            _ => None,
        })
    };
}

/// Searches for the specified node by type, expecting it to exist
macro_rules! expect_and_find_node {
    ($a: expr, $id: expr, $node_type: ident) => {
        find_node!($a, $id, $node_type)
            .or_else(|| {
                panic!("There should be a node of id {:?}!", $id);
            })
            .unwrap()
    };
}

/// Searches for the specified object node, expecting it to exist
macro_rules! expect_and_find_object {
    ($a: expr, $id: expr) => {
        expect_and_find_node!($a, $id, Object)
    };
}

/// Tests if the node of the expected type exists
macro_rules! is_node {
    ($a: expr, $id: expr, $node_type: ident) => {
        if let Some(node) = $a.find_node($id) {
            if let NodeType::$node_type(_) = node {
                true
            } else {
                false
            }
        } else {
            false
        }
    };
}

/// Tests if the object node exists
macro_rules! is_object {
    ($a: expr, $id: expr) => {
        is_node!($a, $id, Object)
    };
}

/// Tests if the method node exists
macro_rules! is_method {
    ($a: expr, $id: expr) => {
        is_node!($a, $id, Method)
    };
}

/// Gets a field from the live diagnostics table.
macro_rules! server_diagnostics_summary {
    ($address_space: expr, $variable_id: expr, $field: ident) => {
        let server_diagnostics = $address_space.server_diagnostics.as_ref().unwrap().clone();
        $address_space.set_variable_getter(
            $variable_id,
            move |_, timestamps_to_return, _, _, _, _| {
                let server_diagnostics = server_diagnostics.read();
                let server_diagnostics_summary = server_diagnostics.server_diagnostics_summary();

                debug!(
                    "Request to get server diagnostics field {}, value = {}",
                    stringify!($variable_id),
                    server_diagnostics_summary.$field
                );

                let mut value = DataValue::from(Variant::from(server_diagnostics_summary.$field));
                let now = DateTime::now();
                value.set_timestamps(timestamps_to_return, now, now);
                Ok(Some(value))
            },
        );
    };
}

pub(crate) type MethodCallback = Box<dyn callbacks::Method + Send + Sync>;

const OPCUA_INTERNAL_NAMESPACE_IDX: u16 = 1;

#[derive(PartialEq, Eq, Clone, Debug, Hash)]
struct MethodKey {
    object_id: NodeId,
    method_id: NodeId,
}

/// The `AddressSpace` describes all of the nodes managed by the server and the references between
/// them. Usually it will be populated with the default OPC UA node set plus any that have been
/// added by the server.
///
/// The `AddressSpace` enforces minimal modelling rules - the implementation is expected to abide
/// by rules when adding nodes. To aid with adding nodes to the address space, each node is
/// a [`NodeType`] which can be one of [`DataType`], [`Object`], [`ObjectType`], [`ReferenceType`], [`Method`],
/// [`Variable`], [`VariableType`] or [`View`]. Each node type has various mandatory and optional
/// attributes that can be set with function calls. In addition, each node type has a corresponding
/// builder, e.g. [`VariableBuilder`] that can be used to simplify adding nodes.
///
/// Some of the methods in `AddressSpace` are liable to change over time especially as more of the
/// heavy lifting is done via builders.
///
/// [`NodeType`]: ../node/enum.NodeType.html
/// [`DataType`]: ../data_type/struct.DataType.html
/// [`Object`]: ../object/struct.Object.html
/// [`ObjectType`]: ../object_type/struct.ObjectType.html
/// [`ReferenceType`]: ../reference_type/struct.ReferenceType.html
/// [`Method`]: ../method/struct.Method.html
/// [`Variable`]: ../variable/struct.Variable.html
/// [`VariableType`]: ../variable_type/struct.VariableType.html
/// [`View`]: ../view/struct.View.html
/// [`VariableBuilder`]: ../variable/struct.VariableBuilder.html
///
pub struct AddressSpace {
    /// A map of all the nodes that are part of the address space
    node_map: HashMap<NodeId, NodeType>,
    /// The references between nodes
    references: References,
    /// This is the last time that nodes or references to nodes were added or removed from the address space.
    last_modified: DateTimeUtc,
    /// Access to server diagnostics
    server_diagnostics: Option<Arc<RwLock<ServerDiagnostics>>>,
    /// The namespace to create sequential node ids
    default_namespace: u16,
    /// The namespace to generate sequential audit node ids
    audit_namespace: u16,
    /// The namespace to generate sequential internal node ids
    internal_namespace: u16,
    /// The list of all registered namespaces.
    namespaces: Vec<String>,
}

impl Default for AddressSpace {
    fn default() -> Self {
        AddressSpace {
            node_map: HashMap::new(),
            references: References::default(),
            last_modified: Utc::now(),
            server_diagnostics: None,
            default_namespace: OPCUA_INTERNAL_NAMESPACE_IDX,
            audit_namespace: OPCUA_INTERNAL_NAMESPACE_IDX,
            internal_namespace: OPCUA_INTERNAL_NAMESPACE_IDX,
            // By default, there will be two standard namespaces. The first is the default
            // OPC UA namespace for its standard nodes. The second is the internal namespace used
            // by this implementation.
            namespaces: vec!["http://opcfoundation.org/UA/".to_string()],
        }
    }
}

impl AddressSpace {
    /// Constructs a default address space consisting of all the nodes and references in the OPC
    /// UA default nodeset.
    pub fn new() -> AddressSpace {
        // Construct the Root folder and the top level nodes
        let mut address_space = AddressSpace::default();
        address_space.add_default_nodes();
        address_space
    }

    /// Returns the last modified date for the address space
    pub fn last_modified(&self) -> DateTimeUtc {
        self.last_modified
    }

    /// Registers a namespace described by a uri with address space. The return code is the index
    /// of the newly added namespace / index. The index is used with `NodeId`. Registering a
    /// namespace that is already registered will return the index to the previous instance.
    /// The last registered namespace becomes the default namespace unless you explcitly call
    /// `set_default_namespace()` after this.
    pub fn register_namespace(&mut self, namespace: &str) -> Result<u16, ()> {
        use std::u16;
        let now = DateTime::now();
        if namespace.is_empty() || self.namespaces.len() == u16::MAX as usize {
            Err(())
        } else {
            // Check if namespace already exists or not
            if let Some(i) = self.namespace_index(namespace) {
                // Existing namespace index
                Ok(i)
            } else {
                // Add and register new namespace
                self.namespaces.push(namespace.into());
                self.set_namespaces(&now);
                // New namespace index
                let ns = (self.namespaces.len() - 1) as u16;
                // Make this the new default namespace
                self.default_namespace = ns;
                Ok(ns)
            }
        }
    }

    /// Finds the namespace index of a given namespace
    pub fn namespace_index(&self, namespace: &str) -> Option<u16> {
        self.namespaces
            .iter()
            .position(|ns| {
                let ns: &str = ns.as_ref();
                ns == namespace
            })
            .map(|i| i as u16)
    }

    fn set_servers(&mut self, server_state: Arc<RwLock<ServerState>>, now: &DateTime) {
        let server_state = trace_read_lock!(server_state);
        if let Some(ref mut v) = self.find_variable_mut(Server_ServerArray) {
            let _ = v.set_value_direct(
                Variant::from(&server_state.servers),
                StatusCode::Good,
                now,
                now,
            );
        }
    }

    fn set_namespaces(&mut self, now: &DateTime) {
        let value = Variant::from(&self.namespaces);
        if let Some(ref mut v) = self.find_variable_mut(Server_NamespaceArray) {
            let _ = v.set_value_direct(value, StatusCode::Good, now, now);
        }
    }

    /// Sets the service level 0-255 worst to best quality of service
    pub fn set_service_level(&mut self, service_level: u8, now: &DateTime) {
        self.set_variable_value(Server_ServiceLevel, service_level, now, now);
    }

    /// Sets values for nodes representing the server.
    pub fn set_server_state(&mut self, server_state: Arc<RwLock<ServerState>>) {
        // Server state requires the generated address space, otherwise nothing
        #[cfg(feature = "generated-address-space")]
        {
            let now = DateTime::now();

            // Servers
            self.set_servers(server_state.clone(), &now);

            // Register the server's application uri as a namespace
            {
                let server_state = trace_read_lock!(server_state);
                let server_config = trace_read_lock!(server_state.config);
                let _ = self.register_namespace(&server_config.application_uri);
            }

            // ServerCapabilities
            {
                let server_state = trace_read_lock!(server_state);
                let server_config = trace_read_lock!(server_state.config);
                self.set_variable_value(
                    Server_ServerCapabilities_MaxArrayLength,
                    server_config.limits.max_array_length as u32,
                    &now,
                    &now,
                );
                self.set_variable_value(
                    Server_ServerCapabilities_MaxStringLength,
                    server_config.limits.max_string_length as u32,
                    &now,
                    &now,
                );
                self.set_variable_value(
                    Server_ServerCapabilities_MaxByteStringLength,
                    server_config.limits.max_byte_string_length as u32,
                    &now,
                    &now,
                );
                self.set_variable_value(
                    Server_ServerCapabilities_MaxBrowseContinuationPoints,
                    constants::MAX_BROWSE_CONTINUATION_POINTS as u32,
                    &now,
                    &now,
                );
                self.set_variable_value(
                    Server_ServerCapabilities_MaxHistoryContinuationPoints,
                    constants::MAX_HISTORY_CONTINUATION_POINTS as u32,
                    &now,
                    &now,
                );
                self.set_variable_value(
                    Server_ServerCapabilities_MaxQueryContinuationPoints,
                    constants::MAX_QUERY_CONTINUATION_POINTS as u32,
                    &now,
                    &now,
                );
                self.set_variable_value(
                    Server_ServerCapabilities_MinSupportedSampleRate,
                    constants::MIN_SAMPLING_INTERVAL as f64,
                    &now,
                    &now,
                );
                let locale_ids: Vec<Variant> = server_config
                    .locale_ids
                    .iter()
                    .map(|v| UAString::from(v).into())
                    .collect();
                self.set_variable_value(
                    Server_ServerCapabilities_LocaleIdArray,
                    (VariantTypeId::String, locale_ids),
                    &now,
                    &now,
                );

                let ol = &server_state.operational_limits;
                self.set_variable_value(
                    Server_ServerCapabilities_OperationLimits_MaxNodesPerRead,
                    ol.max_nodes_per_read as u32,
                    &now,
                    &now,
                );
                self.set_variable_value(
                    Server_ServerCapabilities_OperationLimits_MaxNodesPerWrite,
                    ol.max_nodes_per_write as u32,
                    &now,
                    &now,
                );
                self.set_variable_value(
                    Server_ServerCapabilities_OperationLimits_MaxNodesPerMethodCall,
                    ol.max_nodes_per_method_call as u32,
                    &now,
                    &now,
                );
                self.set_variable_value(
                    Server_ServerCapabilities_OperationLimits_MaxNodesPerBrowse,
                    ol.max_nodes_per_browse as u32,
                    &now,
                    &now,
                );
                self.set_variable_value(
                    Server_ServerCapabilities_OperationLimits_MaxNodesPerRegisterNodes,
                    ol.max_nodes_per_register_nodes as u32,
                    &now,
                    &now,
                );
                self.set_variable_value(Server_ServerCapabilities_OperationLimits_MaxNodesPerTranslateBrowsePathsToNodeIds, ol.max_nodes_per_translate_browse_paths_to_node_ids as u32, &now, &now);
                self.set_variable_value(
                    Server_ServerCapabilities_OperationLimits_MaxNodesPerNodeManagement,
                    ol.max_nodes_per_node_management as u32,
                    &now,
                    &now,
                );
                self.set_variable_value(
                    Server_ServerCapabilities_OperationLimits_MaxMonitoredItemsPerCall,
                    ol.max_monitored_items_per_call as u32,
                    &now,
                    &now,
                );
                self.set_variable_value(
                    Server_ServerCapabilities_OperationLimits_MaxNodesPerHistoryReadData,
                    ol.max_nodes_per_history_read_data as u32,
                    &now,
                    &now,
                );
                self.set_variable_value(
                    Server_ServerCapabilities_OperationLimits_MaxNodesPerHistoryReadEvents,
                    ol.max_nodes_per_history_read_events as u32,
                    &now,
                    &now,
                );
                self.set_variable_value(
                    Server_ServerCapabilities_OperationLimits_MaxNodesPerHistoryUpdateData,
                    ol.max_nodes_per_history_update_data as u32,
                    &now,
                    &now,
                );
                self.set_variable_value(
                    Server_ServerCapabilities_OperationLimits_MaxNodesPerHistoryUpdateEvents,
                    ol.max_nodes_per_history_update_events as u32,
                    &now,
                    &now,
                );
            }

            // Server_ServerCapabilities_ServerProfileArray
            if let Some(ref mut v) =
                self.find_variable_mut(Server_ServerCapabilities_ServerProfileArray)
            {
                // Declares what the server implements. Subitems are implied by the profile. A subitem
                // marked - is optional to the spec
                let server_profiles = [
                    // Base server behaviour
                    //  SecurityPolicy - None
                    //  User Token - User Name Password Server Facet
                    //  Address Space Base
                    //  AttributeRead
                    //  -Attribute Write Index
                    //  -Attribute Write Values
                    //  Base Info Core Structure
                    //  -Base Info OptionSet
                    //  -Base Info Placeholder Modelling Rules
                    //  -Base Info ValueAsText
                    //  Discovery Find Servers Self
                    //  Discovery Get Endpoints
                    //  -Security - No Application Authentications
                    //  -Security - Security Administration
                    //   Session Base
                    //  Session General Service Behaviour
                    //  Session Minimum 1
                    //  View Basic
                    //  View Minimum Continuation Point 01
                    //  View RegisterNodes
                    //  View TranslateBrowsePath
                    "http://opcfoundation.org/UA-Profile/Server/Behaviour",
                    // Embedded UA server
                    //   SecurityPolicy - Basic128Rsa15
                    //     Security
                    //       - Security Certificate Validation
                    //       - Security Basic 128Rsa15
                    //       - Security Encryption Required
                    //       - Security Signing Required
                    //   Standard DataChange Subscription Server Facet
                    //     Base Information
                    //       - Base Info GetMonitoredItems Method
                    //     Monitored Item Services
                    //       - Monitored Items Deadband Filter
                    //       - Monitor Items 10
                    //       - Monitor Items 100
                    //       - Monitor MinQueueSize_02
                    //       - Monitor Triggering
                    //     Subscription Services
                    //       - Subscription Minimum 02
                    //       - Subscription Publish Min 05
                    //     Method Services
                    //       - Method call
                    //   User Token - X509 Certificate Server Facet
                    //       - Security User X509 - Server supports public / private key pair for user identity
                    //   Micro Embedded Device Server Profile
                    // Base Information
                    //   - Base Info Type System - Exposes a Type system with DataTypes, ReferenceTypes, ObjectTypes and VariableTypes
                    //     including all of OPC UA namespace (namespace 0) types that are used by the Server as defined in Part 6.
                    //   - Base Info Placeholder Modelling Rules - The server supports defining cusom Object or Variables that include the use of OptionalPlaceholder
                    //     or MandatoryPlaceholder modelling rules
                    //   - Base Info Engineering Units - The server supports defining Variables that include the Engineering Units property
                    // Security
                    //  Security Default ApplicationInstanceCertificate - has a default ApplicationInstanceCertificate that is valid
                    "http://opcfoundation.org/UA-Profile/Server/EmbeddedUA",
                    // TODO server profile
                    // Standard UA Server Profile
                    //   Enhanced DataChange Subscription Server Facet
                    //     Monitored Item Services
                    //       - Monitor Items 500 - Support at least 500 MonitoredItems per Subscription
                    //       - Monitor MinQueueSize_05 - Support at least 5 queue entries
                    //     Subscription Services
                    //       - Subscription Minimum 05 - Support at least 5 subscriptions per Session
                    //       - Subscription Publish Min 10 - Support at least Publish service requests per session
                    //   Embedded UA Server Profile
                    // Base Information
                    //   - Base Info Diagnostics
                    // Discovery Services
                    //   - Discovery Register (be able to call RegisterServer)
                    //   - Discovery Register2 (be able to call RegisterServer2)
                    // Session Services
                    //   - Session Change User - Support use of ActivateSession to change the Session user
                    //   - Session Cancel - Support the Cancel Service to cancel outstanding requests
                    //   - Session Minimum 50 Parallel - Support minimum 50 parallel Sessions
                    //
                    // "http://opcfoundation.org/UA-Profile/Server/StandardUA",
                ];
                let _ = v.set_value_direct(
                    Variant::from((VariantTypeId::String, &server_profiles[..])),
                    StatusCode::Good,
                    &now,
                    &now,
                );
            }

            // Server_ServerDiagnostics_ServerDiagnosticsSummary
            // Server_ServerDiagnostics_SamplingIntervalDiagnosticsArray
            // Server_ServerDiagnostics_SubscriptionDiagnosticsArray
            // Server_ServerDiagnostics_EnabledFlag
            {
                let server_state = trace_read_lock!(server_state);
                self.server_diagnostics = Some(server_state.diagnostics.clone());
                server_diagnostics_summary!(
                    self,
                    Server_ServerDiagnostics_ServerDiagnosticsSummary_ServerViewCount,
                    server_view_count
                );
                server_diagnostics_summary!(
                    self,
                    Server_ServerDiagnostics_ServerDiagnosticsSummary_CurrentSessionCount,
                    current_session_count
                );
                server_diagnostics_summary!(
                    self,
                    Server_ServerDiagnostics_ServerDiagnosticsSummary_CumulatedSessionCount,
                    cumulated_session_count
                );
                server_diagnostics_summary!(
                    self,
                    Server_ServerDiagnostics_ServerDiagnosticsSummary_SecurityRejectedSessionCount,
                    security_rejected_session_count
                );
                server_diagnostics_summary!(
                    self,
                    Server_ServerDiagnostics_ServerDiagnosticsSummary_SessionTimeoutCount,
                    session_timeout_count
                );
                server_diagnostics_summary!(
                    self,
                    Server_ServerDiagnostics_ServerDiagnosticsSummary_SessionAbortCount,
                    session_abort_count
                );
                server_diagnostics_summary!(
                    self,
                    Server_ServerDiagnostics_ServerDiagnosticsSummary_RejectedSessionCount,
                    rejected_session_count
                );
                server_diagnostics_summary!(
                    self,
                    Server_ServerDiagnostics_ServerDiagnosticsSummary_PublishingIntervalCount,
                    publishing_interval_count
                );
                server_diagnostics_summary!(
                    self,
                    Server_ServerDiagnostics_ServerDiagnosticsSummary_CurrentSubscriptionCount,
                    current_subscription_count
                );
                server_diagnostics_summary!(
                    self,
                    Server_ServerDiagnostics_ServerDiagnosticsSummary_CumulatedSubscriptionCount,
                    cumulated_subscription_count
                );
                server_diagnostics_summary!(
                    self,
                    Server_ServerDiagnostics_ServerDiagnosticsSummary_SecurityRejectedRequestsCount,
                    security_rejected_requests_count
                );
                server_diagnostics_summary!(
                    self,
                    Server_ServerDiagnostics_ServerDiagnosticsSummary_RejectedRequestsCount,
                    rejected_requests_count
                );
            }

            // ServiceLevel - 0-255 worst to best quality of service
            self.set_service_level(255u8, &now);

            // Auditing - var
            // ServerDiagnostics
            // VendorServiceInfo
            // ServerRedundancy

            // Server_ServerStatus_StartTime
            self.set_variable_value(Server_ServerStatus_StartTime, now, &now, &now);

            // Server_ServerStatus_CurrentTime
            self.set_variable_getter(
                Server_ServerStatus_CurrentTime,
                move |_, timestamps_to_return, _, _, _, _| {
                    let now = DateTime::now();
                    let mut value = DataValue::from(now);
                    value.set_timestamps(timestamps_to_return, now, now);
                    Ok(Some(value))
                },
            );

            // State OPC UA Part 5 12.6, Valid states are
            //     State (Server_ServerStatus_State)
            self.set_variable_getter(
                Server_ServerStatus_State,
                move |_, timestamps_to_return, _, _, _, _| {
                    // let server_state =  trace_read_lock!(server_state);
                    let now = DateTime::now();
                    let mut value = DataValue::from(0i32);
                    value.set_timestamps(timestamps_to_return, now, now);
                    Ok(Some(value))
                },
            );

            // ServerStatus_BuildInfo
            {
                //    BuildDate
                //    BuildNumber
                //    ManufacturerName
                //    ProductName
                //    ProductUri
                //    SoftwareVersion
            }

            // Server method handlers
            use crate::server::address_space::method_impls;
            self.register_method_handler(
                MethodId::Server_ResendData,
                Box::new(method_impls::ServerResendDataMethod),
            );
            self.register_method_handler(
                MethodId::Server_GetMonitoredItems,
                Box::new(method_impls::ServerGetMonitoredItemsMethod),
            );
        }
    }

    /// Sets the history server capabilities based on the supplied flags
    pub fn set_history_server_capabilities(&mut self, capabilities: &HistoryServerCapabilities) {
        let now = DateTime::now();
        self.set_variable_value(
            HistoryServerCapabilities_AccessHistoryDataCapability,
            capabilities.access_history_data,
            &now,
            &now,
        );
        self.set_variable_value(
            HistoryServerCapabilities_AccessHistoryEventsCapability,
            capabilities.access_history_events,
            &now,
            &now,
        );
        self.set_variable_value(
            HistoryServerCapabilities_MaxReturnDataValues,
            capabilities.max_return_data,
            &now,
            &now,
        );
        self.set_variable_value(
            HistoryServerCapabilities_MaxReturnEventValues,
            capabilities.max_return_events,
            &now,
            &now,
        );
        self.set_variable_value(
            HistoryServerCapabilities_InsertDataCapability,
            capabilities.insert_data,
            &now,
            &now,
        );
        self.set_variable_value(
            HistoryServerCapabilities_ReplaceDataCapability,
            capabilities.replace_data,
            &now,
            &now,
        );
        self.set_variable_value(
            HistoryServerCapabilities_UpdateDataCapability,
            capabilities.update_data,
            &now,
            &now,
        );
        self.set_variable_value(
            HistoryServerCapabilities_DeleteRawCapability,
            capabilities.delete_raw,
            &now,
            &now,
        );
        self.set_variable_value(
            HistoryServerCapabilities_DeleteAtTimeCapability,
            capabilities.delete_at_time,
            &now,
            &now,
        );
        self.set_variable_value(
            HistoryServerCapabilities_InsertEventCapability,
            capabilities.insert_event,
            &now,
            &now,
        );
        self.set_variable_value(
            HistoryServerCapabilities_ReplaceEventCapability,
            capabilities.replace_event,
            &now,
            &now,
        );
        self.set_variable_value(
            HistoryServerCapabilities_UpdateEventCapability,
            capabilities.update_event,
            &now,
            &now,
        );
        self.set_variable_value(
            HistoryServerCapabilities_InsertAnnotationCapability,
            capabilities.insert_annotation,
            &now,
            &now,
        );
    }

    /// Returns the root folder
    pub fn root_folder(&self) -> &Object {
        expect_and_find_object!(self, &NodeId::root_folder_id())
    }

    /// Returns the objects folder
    pub fn objects_folder(&self) -> &Object {
        expect_and_find_object!(self, &NodeId::objects_folder_id())
    }

    /// Returns the types folder
    pub fn types_folder(&self) -> &Object {
        expect_and_find_object!(self, &NodeId::types_folder_id())
    }

    /// Returns the views folder
    pub fn views_folder(&self) -> &Object {
        expect_and_find_object!(self, &NodeId::views_folder_id())
    }

    fn assert_namespace(&self, node_id: &NodeId) {
        if node_id.namespace as usize > self.namespaces.len() {
            panic!("Namespace index {} does not exist", node_id.namespace);
        }
    }

    /// Sets the default namespace
    pub fn set_default_namespace(&mut self, default_namespace: u16) {
        self.default_namespace = default_namespace;
    }

    /// Gets the default namespace
    pub fn default_namespace(&self) -> u16 {
        self.default_namespace
    }

    /// Get the default namespace for audit events
    pub fn audit_namespace(&self) -> u16 {
        self.audit_namespace
    }

    /// Get the internal namespace
    pub fn internal_namespace(&self) -> u16 {
        self.internal_namespace
    }

    /// Inserts a node into the address space node map and its references to other target nodes.
    /// The tuple of references is the target node id, reference type id and a bool which is false for
    /// a forward reference and indicating inverse
    pub fn insert<T, S>(
        &mut self,
        node: T,
        references: Option<&[(&NodeId, &S, ReferenceDirection)]>,
    ) -> bool
    where
        T: Into<NodeType>,
        S: Into<NodeId> + Clone,
    {
        let node_type = node.into();
        let node_id = node_type.node_id();

        self.assert_namespace(&node_id);

        if self.node_exists(&node_id) {
            error!("This node {} already exists", node_id);
            false
        } else {
            self.node_map.insert(node_id.clone(), node_type);
            // If references are supplied, add them now
            if let Some(references) = references {
                self.references.insert(&node_id, references);
            }
            self.update_last_modified();
            true
        }
    }

    /// Adds the standard nodeset to the address space
    pub fn add_default_nodes(&mut self) {
        debug!("populating address space");

        #[cfg(feature = "generated-address-space")]
        {
            // Reserve space in the maps. The default node set contains just under 2000 values for
            // nodes, references and inverse references.
            self.node_map.reserve(2000);
            // Run the generated code that will populate the address space with the default nodes
            super::generated::populate_address_space(self);
        }
    }

    // Inserts a bunch of references between two nodes into the address space
    pub fn insert_references<T>(&mut self, references: &[(&NodeId, &NodeId, &T)])
    where
        T: Into<NodeId> + Clone,
    {
        self.references.insert_references(references);
        self.update_last_modified();
    }

    /// Inserts a single reference between two nodes in the address space
    pub fn insert_reference<T>(
        &mut self,
        node_id: &NodeId,
        target_node_id: &NodeId,
        reference_type_id: T,
    ) where
        T: Into<NodeId> + Clone,
    {
        self.references
            .insert_reference(node_id, target_node_id, &reference_type_id);
        self.update_last_modified();
    }

    pub fn set_node_type<T>(&mut self, node_id: &NodeId, node_type: T)
    where
        T: Into<NodeId>,
    {
        self.insert_reference(
            node_id,
            &node_type.into(),
            ReferenceTypeId::HasTypeDefinition,
        );
    }

    pub fn node_exists(&self, node_id: &NodeId) -> bool {
        self.node_map.contains_key(node_id)
    }

    /// Adds a folder with a specified id
    pub fn add_folder_with_id<R, S>(
        &mut self,
        node_id: &NodeId,
        browse_name: R,
        display_name: S,
        parent_node_id: &NodeId,
    ) -> bool
    where
        R: Into<QualifiedName>,
        S: Into<LocalizedText>,
    {
        self.assert_namespace(node_id);
        ObjectBuilder::new(node_id, browse_name, display_name)
            .is_folder()
            .organized_by(parent_node_id.clone())
            .insert(self)
    }

    /// Adds a folder using a generated node id
    pub fn add_folder<R, S>(
        &mut self,
        browse_name: R,
        display_name: S,
        parent_node_id: &NodeId,
    ) -> Result<NodeId, ()>
    where
        R: Into<QualifiedName>,
        S: Into<LocalizedText>,
    {
        let node_id = NodeId::next_numeric(self.default_namespace);
        self.assert_namespace(&node_id);
        if self.add_folder_with_id(&node_id, browse_name, display_name, parent_node_id) {
            Ok(node_id)
        } else {
            Err(())
        }
    }

    /// Adds a list of variables to the specified parent node
    pub fn add_variables(
        &mut self,
        variables: Vec<Variable>,
        parent_node_id: &NodeId,
    ) -> Vec<bool> {
        let result = variables
            .into_iter()
            .map(|v| {
                self.insert(
                    v,
                    Some(&[(
                        parent_node_id,
                        &ReferenceTypeId::Organizes,
                        ReferenceDirection::Inverse,
                    )]),
                )
            })
            .collect();
        self.update_last_modified();
        result
    }

    /// Deletes a node by its node id, and all of its properties and optionally any references to or from it it in the
    /// address space.
    pub fn delete(&mut self, node_id: &NodeId, delete_target_references: bool) -> bool {
        // Delete any children recursively
        if let Some(child_nodes) = self.find_aggregates_of(node_id) {
            child_nodes.into_iter().for_each(|node_id| {
                debug!("Deleting child node {}", node_id);
                let _ = self.delete(&node_id, delete_target_references);
            });
        }
        // Remove the node
        let removed_node = self.node_map.remove(node_id);
        // Remove references
        let removed_target_references = if delete_target_references {
            self.references.delete_node_references(node_id)
        } else {
            false
        };
        removed_node.is_some() || removed_target_references
    }

    /// Finds the matching reference and deletes it
    pub fn delete_reference<T>(
        &mut self,
        node_id: &NodeId,
        target_node_id: &NodeId,
        reference_type_id: T,
    ) -> bool
    where
        T: Into<NodeId>,
    {
        self.references
            .delete_reference(node_id, target_node_id, reference_type_id)
    }

    /// Find node by something that can be turned into a node id and return a reference to it.
    pub fn find<N>(&self, node_id: N) -> Option<&NodeType>
    where
        N: Into<NodeId>,
    {
        self.find_node(&node_id.into())
    }

    /// Find node by something that can be turned into a node id and return a mutable reference to it.
    pub fn find_mut<N>(&mut self, node_id: N) -> Option<&mut NodeType>
    where
        N: Into<NodeId>,
    {
        self.find_node_mut(&node_id.into())
    }

    /// Finds a node by its node id and returns a reference to it.
    pub fn find_node(&self, node_id: &NodeId) -> Option<&NodeType> {
        self.node_map.get(node_id)
    }

    /// Finds a node by its node id and returns a mutable reference to it.
    pub fn find_node_mut(&mut self, node_id: &NodeId) -> Option<&mut NodeType> {
        self.node_map.get_mut(node_id)
    }

    /// Find and return a variable with the specified node id or return None if it cannot be
    /// found or is not a variable
    pub fn find_variable<N>(&self, node_id: N) -> Option<&Variable>
    where
        N: Into<NodeId>,
    {
        self.find_variable_by_ref(&node_id.into())
    }

    /// Find and return a variable with the specified node id or return None if it cannot be
    /// found or is not a variable
    pub fn find_variable_by_ref(&self, node_id: &NodeId) -> Option<&Variable> {
        find_node!(self, node_id, Variable)
    }

    /// Find and return a variable with the specified node id or return None if it cannot be
    /// found or is not a variable
    pub fn find_variable_mut<N>(&mut self, node_id: N) -> Option<&mut Variable>
    where
        N: Into<NodeId>,
    {
        self.find_variable_mut_by_ref(&node_id.into())
    }

    /// Find and return a variable with the specified node id or return None if it cannot be
    /// found or is not a variable
    pub fn find_variable_mut_by_ref(&mut self, node_id: &NodeId) -> Option<&mut Variable> {
        find_node_mut!(self, node_id, Variable)
    }

    /// Set a variable value from its NodeId. The function will return false if the variable does
    /// not exist, or the node is not a variable.
    pub fn set_variable_value<N, V>(
        &mut self,
        node_id: N,
        value: V,
        source_timestamp: &DateTime,
        server_timestamp: &DateTime,
    ) -> bool
    where
        N: Into<NodeId>,
        V: Into<Variant>,
    {
        self.set_variable_value_by_ref(&node_id.into(), value, source_timestamp, server_timestamp)
    }

    /// Set a variable value from its NodeId. The function will return false if the variable does
    /// not exist, or the node is not a variable.
    pub fn set_variable_value_by_ref<V>(
        &mut self,
        node_id: &NodeId,
        value: V,
        source_timestamp: &DateTime,
        server_timestamp: &DateTime,
    ) -> bool
    where
        V: Into<Variant>,
    {
        if let Some(ref mut variable) = self.find_variable_mut_by_ref(node_id) {
            let _ = variable.set_value_direct(
                value,
                StatusCode::Good,
                source_timestamp,
                server_timestamp,
            );
            true
        } else {
            false
        }
    }

    /// Gets a variable value with the supplied NodeId. The function will return Err if the
    /// NodeId does not exist or is not a variable.
    pub fn get_variable_value<N>(&self, node_id: N) -> Result<DataValue, ()>
    where
        N: Into<NodeId>,
    {
        self.find_variable(node_id)
            .map(|variable| {
                variable.value(
                    TimestampsToReturn::Neither,
                    NumericRange::None,
                    &QualifiedName::null(),
                    0.0,
                )
            })
            .ok_or_else(|| ())
    }

    /// Registers a method callback on the specified object id and method id
    pub fn register_method_handler<N>(&mut self, method_id: N, handler: MethodCallback)
    where
        N: Into<NodeId>,
    {
        // Check the object id and method id actually exist as things in the address space
        let method_id = method_id.into();
        if let Some(method) = self.find_mut(&method_id) {
            match method {
                NodeType::Method(method) => method.set_callback(handler),
                _ => panic!("{} is not a method node", method_id),
            }
        } else {
            panic!("{} method id does not exist", method_id);
        }
    }

    /// Test if the type definition is defined and valid for a class of the specified type.
    /// i.e. if we have a Variable or Object class that the type is a VariableType or ObjectType
    /// respectively.
    pub fn is_valid_type_definition(
        &self,
        node_class: NodeClass,
        type_definition: &NodeId,
    ) -> bool {
        match node_class {
            NodeClass::Object => {
                if type_definition.is_null() {
                    false
                } else if let Some(NodeType::ObjectType(_)) = self.find_node(type_definition) {
                    true
                } else {
                    false
                }
            }
            NodeClass::Variable => {
                if type_definition.is_null() {
                    false
                } else if let Some(NodeType::VariableType(_)) = self.find_node(type_definition) {
                    true
                } else {
                    false
                }
            }
            _ => {
                // Other node classes must NOT supply a type definition
                type_definition.is_null()
            }
        }
    }

    /// This finds the type definition (if any corresponding to the input object)
    fn get_type_id(&self, node_id: &NodeId) -> Option<NodeId> {
        self.references.get_type_id(node_id)
    }

    /// Test if a reference relationship exists between one node and another node
    pub fn has_reference<T>(
        &self,
        source_node: &NodeId,
        target_node: &NodeId,
        reference_type: T,
    ) -> bool
    where
        T: Into<NodeId>,
    {
        self.references
            .has_reference(source_node, target_node, reference_type)
    }

    /// Tests if a method exists on a specific object. This will be true if the method id is
    /// a HasComponent of the object itself, or a HasComponent of the object type
    fn method_exists_on_object(&self, object_id: &NodeId, method_id: &NodeId) -> bool {
        // Look for the method first on the object id, else on the object's type
        if self.has_reference(object_id, method_id, ReferenceTypeId::HasComponent) {
            true
        } else if let Some(object_type_id) = self.get_type_id(object_id) {
            self.has_reference(&object_type_id, method_id, ReferenceTypeId::HasComponent)
        } else {
            error!("Method call to {:?} on {:?} but the method id is not on the object or its object type!", method_id, object_id);
            false
        }
    }

    /// Calls a method node with the supplied request and expecting a result.
    ///
    /// Calls require a registered handler to handle the method. If there is no handler, or if
    /// the request refers to a non existent object / method, the function will return an error.
    pub fn call_method(
        &mut self,
        _server_state: &ServerState,
        session_id: &NodeId,
        session_manager: Arc<RwLock<SessionManager>>,
        request: &CallMethodRequest,
    ) -> Result<CallMethodResult, StatusCode> {
        let (object_id, method_id) = (&request.object_id, &request.method_id);
        // Handle the call
        if !is_object!(self, object_id) {
            error!(
                "Method call to {:?} on {:?} but the node id is not recognized!",
                method_id, object_id
            );
            Err(StatusCode::BadNodeIdUnknown)
        } else if !is_method!(self, method_id) {
            error!(
                "Method call to {:?} on {:?} but the method id is not recognized!",
                method_id, object_id
            );
            Err(StatusCode::BadMethodInvalid)
        } else if !self.method_exists_on_object(object_id, method_id) {
            error!(
                "Method call to {:?} on {:?} but the method does not exist on the object!",
                method_id, object_id
            );
            Err(StatusCode::BadMethodInvalid)
        } else if let Some(method) = self.find_mut(method_id) {
            // TODO check security - session / user may not have permission to call methods
            match method {
                NodeType::Method(method) => method.call(session_id, session_manager, request),
                _ => Err(StatusCode::BadMethodInvalid),
            }
        } else {
            Err(StatusCode::BadMethodInvalid)
        }
    }

    /// Recursive function tries to find if a type is a subtype of another type by looking at its
    /// references. Function will positively match a type against itself.
    pub fn is_subtype(&self, subtype_id: &NodeId, base_type_id: &NodeId) -> bool {
        subtype_id == base_type_id || {
            // Apply same test to all children of the base type
            if let Some(references) =
                self.find_references(base_type_id, Some((ReferenceTypeId::HasSubtype, false)))
            {
                // Each child will test if it is the parent / match for the subtype
                references
                    .iter()
                    .any(|r| self.is_subtype(subtype_id, &r.target_node))
            } else {
                false
            }
        }
    }
    /// Finds objects by a specified type.
    fn find_nodes_by_type<T>(
        &self,
        node_type_class: NodeClass,
        node_type_id: T,
        include_subtypes: bool,
    ) -> Option<Vec<NodeId>>
    where
        T: Into<NodeId>,
    {
        let node_type_id = node_type_id.into();
        // Ensure the node type is of the right class
        if let Some(node) = self.node_map.get(&node_type_id) {
            if node.node_class() == node_type_class {
                // Find nodes with a matching type definition
                let nodes = self
                    .node_map
                    .iter()
                    .filter(|(_, v)| v.node_class() == NodeClass::Object)
                    .filter(move |(k, _)| {
                        // Node has to have a type definition reference to the type
                        if let Some(type_refs) = self
                            .find_references(k, Some((ReferenceTypeId::HasTypeDefinition, false)))
                        {
                            // Type definition must find the sought after type
                            type_refs.iter().any(|r| {
                                include_subtypes && self.is_subtype(&node_type_id, &r.target_node)
                                    || r.target_node == node_type_id
                            })
                        } else {
                            false
                        }
                    })
                    .map(|(k, _)| k.clone())
                    .collect::<Vec<NodeId>>();
                if nodes.is_empty() {
                    None
                } else {
                    Some(nodes)
                }
            } else {
                debug!("Cannot find nodes by type because node type id {:?} is not a matching class {:?}", node_type_id, node_type_class);
                None
            }
        } else {
            debug!(
                "Cannot find nodes by type because node type id {:?} does not exist",
                node_type_id
            );
            None
        }
    }

    pub fn find_objects_by_type<T>(
        &self,
        object_type: T,
        include_subtypes: bool,
    ) -> Option<Vec<NodeId>>
    where
        T: Into<NodeId>,
    {
        self.find_nodes_by_type(NodeClass::ObjectType, object_type, include_subtypes)
    }

    pub fn find_variables_by_type<T>(
        &self,
        variable_type: T,
        include_subtypes: bool,
    ) -> Option<Vec<NodeId>>
    where
        T: Into<NodeId>,
    {
        self.find_nodes_by_type(NodeClass::VariableType, variable_type, include_subtypes)
    }

    /// Finds all child propertiesof the parent node. i.e. Aggregates or any subtype
    pub fn find_aggregates_of(&self, parent_node: &NodeId) -> Option<Vec<NodeId>> {
        self.find_references(parent_node, Some((ReferenceTypeId::Aggregates, true)))
            .map(|references| {
                references
                    .iter()
                    .map(|r| {
                        // debug!("reference {:?}", r);
                        r.target_node.clone()
                    })
                    .collect()
            })
    }

    /// Finds hierarchical references of the parent node, i.e. children, event sources, organizes etc from the parent node to other nodes.
    /// This function will return node ids even if the nodes themselves do not exist in the address space.
    pub fn find_hierarchical_references(&self, parent_node: &NodeId) -> Option<Vec<NodeId>> {
        self.find_references(
            parent_node,
            Some((ReferenceTypeId::HierarchicalReferences, true)),
        )
        .map(|references| {
            references
                .iter()
                .map(|r| {
                    // debug!("reference {:?}", r);
                    r.target_node.clone()
                })
                .collect()
        })
    }

    /// Finds forward references from the specified node. The reference filter can optionally filter results
    /// by a specific type and subtypes.
    pub fn find_references<T>(
        &self,
        node: &NodeId,
        reference_filter: Option<(T, bool)>,
    ) -> Option<Vec<Reference>>
    where
        T: Into<NodeId> + Clone,
    {
        self.references.find_references(node, reference_filter)
    }

    /// Finds inverse references, it those that point to the specified node. The reference filter can
    /// optionally filter results by a specific type and subtypes.
    pub fn find_inverse_references<T>(
        &self,
        node: &NodeId,
        reference_filter: Option<(T, bool)>,
    ) -> Option<Vec<Reference>>
    where
        T: Into<NodeId> + Clone,
    {
        self.references
            .find_inverse_references(node, reference_filter)
    }

    /// Finds references for optionally forwards, inverse or both and return the references. The usize
    /// represents the index in the collection where the inverse references start (if applicable)
    pub fn find_references_by_direction<T>(
        &self,
        node_id: &NodeId,
        browse_direction: BrowseDirection,
        reference_filter: Option<(T, bool)>,
    ) -> (Vec<Reference>, usize)
    where
        T: Into<NodeId> + Clone,
    {
        self.references
            .find_references_by_direction(node_id, browse_direction, reference_filter)
    }

    /// Updates the last modified timestamp to now
    fn update_last_modified(&mut self) {
        self.last_modified = Utc::now();
    }

    /// Sets the getter for a variable node
    fn set_variable_getter<N, F>(&mut self, variable_id: N, getter: F)
    where
        N: Into<NodeId>,
        F: FnMut(
                &NodeId,
                TimestampsToReturn,
                AttributeId,
                NumericRange,
                &QualifiedName,
                f64,
            ) -> Result<Option<DataValue>, StatusCode>
            + Send
            + 'static,
    {
        if let Some(ref mut v) = self.find_variable_mut(variable_id) {
            let getter = AttrFnGetter::new(getter);
            v.set_value_getter(Arc::new(Mutex::new(getter)));
        }
    }

    /// Returns the references
    pub fn references(&self) -> &References {
        &self.references
    }
}
