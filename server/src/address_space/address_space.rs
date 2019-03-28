use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

use chrono::Utc;

use opcua_types::{
    *,
    node_ids::*,
    status_code::StatusCode,
    service_types::{CallMethodRequest, CallMethodResult, BrowseDirection, NodeClass},
};

use crate::{
    address_space::{
        AttrFnGetter,
        node::{Node, NodeType, HasNodeId},
        object::Object,
        variable::Variable,
        method_impls,
        references::{References, Reference, ReferenceDirection},
    },
    diagnostics::ServerDiagnostics,
    state::ServerState,
    session::Session,
    constants,
    DateTimeUtc,
};

/// Searches for the specified node by type, expecting it to exist
macro_rules! expect_and_find_node {
    ($a: expr, $id: expr, $type: ident) => {
        if let &NodeType::$type(ref node) = $a.find_node($id).unwrap() {
            node
        } else {
            panic!("There should be a node of id {:?}!", $id);
        }
    }
}

/// Searches for the specified object node, expecting it to exist
macro_rules! expect_and_find_object {
    ($a: expr, $id: expr) => {
        expect_and_find_node!($a, $id, Object)
    }
}

/// Tests if the node of the expected type exists
macro_rules! is_node {
    ($a: expr, $id: expr, $type: ident) => {
        if let Some(node) = $a.find_node($id) {
            if let NodeType::$type(_) = node {
                true
            } else {
                false
            }
        } else {
            false
        }
    }
}

/// Tests if the object node exists
macro_rules! is_object {
    ($a: expr, $id: expr) => {
        is_node!($a, $id, Object)
    }
}

/// Tests if the method node exists
macro_rules! is_method {
    ($a: expr, $id: expr) => {
        is_node!($a, $id, Method)
    }
}

/// Gets a field from the live diagnostics table.
macro_rules! server_diagnostics_summary {
    ($address_space: expr, $variable_id: expr, $field: ident) => {
        let server_diagnostics = $address_space.server_diagnostics.as_ref().unwrap().clone();
        $address_space.set_variable_getter($variable_id, move |_, _, _| {
            let server_diagnostics = server_diagnostics.read().unwrap();
            let server_diagnostics_summary = server_diagnostics.server_diagnostics_summary();
            Ok(Some(DataValue::from(Variant::from(server_diagnostics_summary.$field))))
        });
    }
}

type MethodCallback = Box<dyn Fn(&AddressSpace, &ServerState, &mut Session, &CallMethodRequest) -> Result<CallMethodResult, StatusCode> + Send + Sync + 'static>;

#[derive(PartialEq, Eq, Clone, Debug, Hash)]
struct MethodKey {
    object_id: NodeId,
    method_id: NodeId,
}

/// The address space holds references between nodes. It is populated with some standard nodes
/// and any that the server implementation chooses to add for itself.
pub struct AddressSpace {
    /// A map of all the nodes that are part of the address space
    node_map: HashMap<NodeId, NodeType>,
    /// The references between nodes
    references: References,
    /// This is the last time that nodes or references to nodes were added or removed from the address space.
    last_modified: DateTimeUtc,
    /// Method handlers
    method_handlers: HashMap<MethodKey, MethodCallback>,
    /// Access to server diagnostics
    server_diagnostics: Option<Arc<RwLock<ServerDiagnostics>>>,
}

impl AddressSpace {
    /// Constructs a default address space. That consists of all the nodes in the implementation's
    /// supported profile.
    pub fn new() -> AddressSpace {
        // Construct the Root folder and the top level nodes
        let mut address_space = AddressSpace {
            node_map: HashMap::new(),
            references: References::default(),
            last_modified: Utc::now(),
            method_handlers: HashMap::new(),
            server_diagnostics: None,
        };
        address_space.add_default_nodes();
        address_space
    }

    /// Returns the last modified date for the address space
    pub fn last_modified(&self) -> DateTimeUtc {
        self.last_modified.clone()
    }

    /// Sets the getter for a variable node
    pub fn set_variable_getter<N, F>(&mut self, variable_id: N, getter: F) where
        N: Into<NodeId>,
        F: FnMut(&NodeId, AttributeId, f64) -> Result<Option<DataValue>, StatusCode> + Send + 'static
    {
        if let Some(ref mut v) = self.find_variable_mut(variable_id) {
            let getter = AttrFnGetter::new(getter);
            v.set_value_getter(Arc::new(Mutex::new(getter)));
        }
    }

    /// Sets values for nodes representing the server.
    pub fn set_server_state(&mut self, server_state: Arc<RwLock<ServerState>>) {
        use opcua_types::node_ids::VariableId::*;

        let now = DateTime::now();

        // Server variables
        {
            let server_state = trace_read_lock_unwrap!(server_state);
            if let Some(ref mut v) = self.find_variable_mut(Server_NamespaceArray) {
                v.set_value_direct(Variant::from(&server_state.namespaces), &now, &now);
            }
            if let Some(ref mut v) = self.find_variable_mut(Server_ServerArray) {
                v.set_value_direct(Variant::from(&server_state.servers), &now, &now);
            }
        }

        // ServerCapabilities
        {
            let server_state = trace_read_lock_unwrap!(server_state);
            let server_config = trace_read_lock_unwrap!(server_state.config);
            self.set_variable_value(Server_ServerCapabilities_MaxArrayLength, server_config.max_array_length as u32, &now, &now);
            self.set_variable_value(Server_ServerCapabilities_MaxStringLength, server_config.max_string_length as u32, &now, &now);
            self.set_variable_value(Server_ServerCapabilities_MaxByteStringLength, server_config.max_byte_string_length as u32, &now, &now);
            self.set_variable_value(Server_ServerCapabilities_MaxBrowseContinuationPoints, constants::MAX_BROWSE_CONTINUATION_POINTS as u32, &now, &now);
            self.set_variable_value(Server_ServerCapabilities_MaxHistoryContinuationPoints, constants::MAX_HISTORY_CONTINUATION_POINTS as u32, &now, &now);
            self.set_variable_value(Server_ServerCapabilities_MaxQueryContinuationPoints, constants::MAX_QUERY_CONTINUATION_POINTS as u32, &now, &now);
            self.set_variable_value(Server_ServerCapabilities_MinSupportedSampleRate, constants::MIN_SAMPLING_INTERVAL as f64, &now, &now);
        }

        // Server_ServerCapabilities_ServerProfileArray
        if let Some(ref mut v) = self.find_variable_mut(Server_ServerCapabilities_ServerProfileArray) {
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
            v.set_value_direct(Variant::from(&server_profiles[..]), &now, &now);
        }

        // Server_ServerCapabilities_LocaleIdArray
        // Server_ServerCapabilities_MinSupportedSampleRate

        // Server_ServerDiagnostics_ServerDiagnosticsSummary
        // Server_ServerDiagnostics_SamplingIntervalDiagnosticsArray
        // Server_ServerDiagnostics_SubscriptionDiagnosticsArray
        // Server_ServerDiagnostics_EnabledFlag
        {
            let server_state = trace_read_lock_unwrap!(server_state);
            self.server_diagnostics = Some(server_state.diagnostics.clone());
            server_diagnostics_summary!(self, Server_ServerDiagnostics_ServerDiagnosticsSummary_ServerViewCount, server_view_count);
            server_diagnostics_summary!(self, Server_ServerDiagnostics_ServerDiagnosticsSummary_CurrentSessionCount, current_session_count);
            server_diagnostics_summary!(self, Server_ServerDiagnostics_ServerDiagnosticsSummary_CumulatedSessionCount, cumulated_session_count);
            server_diagnostics_summary!(self, Server_ServerDiagnostics_ServerDiagnosticsSummary_SecurityRejectedSessionCount, security_rejected_session_count);
            server_diagnostics_summary!(self, Server_ServerDiagnostics_ServerDiagnosticsSummary_SessionTimeoutCount, session_timeout_count);
            server_diagnostics_summary!(self, Server_ServerDiagnostics_ServerDiagnosticsSummary_SessionAbortCount, session_abort_count);
            server_diagnostics_summary!(self, Server_ServerDiagnostics_ServerDiagnosticsSummary_RejectedSessionCount, rejected_session_count);
            server_diagnostics_summary!(self, Server_ServerDiagnostics_ServerDiagnosticsSummary_PublishingIntervalCount, publishing_interval_count);
            server_diagnostics_summary!(self, Server_ServerDiagnostics_ServerDiagnosticsSummary_CurrentSubscriptionCount, current_subscription_count);
            server_diagnostics_summary!(self, Server_ServerDiagnostics_ServerDiagnosticsSummary_CumulatedSubscriptionCount, cumulated_subscription_count);
            server_diagnostics_summary!(self, Server_ServerDiagnostics_ServerDiagnosticsSummary_SecurityRejectedRequestsCount, security_rejected_requests_count);
            server_diagnostics_summary!(self, Server_ServerDiagnostics_ServerDiagnosticsSummary_RejectedRequestsCount, rejected_requests_count);
        }

        // Server_ServerCapabilities_OperationLimits_MaxNodesPerRead = 11705,
        // Server_ServerCapabilities_OperationLimits_MaxNodesPerWrite = 11707,
        // Server_ServerCapabilities_OperationLimits_MaxNodesPerMethodCall = 11709,
        // Server_ServerCapabilities_OperationLimits_MaxNodesPerBrowse = 11710,
        // Server_ServerCapabilities_OperationLimits_MaxNodesPerRegisterNodes = 11711,
        // Server_ServerCapabilities_OperationLimits_MaxNodesPerTranslateBrowsePathsToNodeIds = 11712,
        // Server_ServerCapabilities_OperationLimits_MaxNodesPerNodeManagement = 11713,
        // Server_ServerCapabilities_OperationLimits_MaxMonitoredItemsPerCall = 11714,
        // Server_ServerCapabilities_OperationLimits_MaxNodesPerHistoryReadData = 12165,
        // Server_ServerCapabilities_OperationLimits_MaxNodesPerHistoryReadEvents = 12166,
        // Server_ServerCapabilities_OperationLimits_MaxNodesPerHistoryUpdateData = 12167,
        // Server_ServerCapabilities_OperationLimits_MaxNodesPerHistoryUpdateEvents = 12168,

        // ServiceLevel - 0-255 worst to best quality of service
        self.set_variable_value(Server_ServiceLevel, 255u8, &now, &now);

        // Auditing - var
        // ServerDiagnostics
        // VendorServiceInfo
        // ServerRedundancy

        // Server_ServerStatus_StartTime
        self.set_variable_value(Server_ServerStatus_StartTime, now.clone(), &now, &now);

        // Server_ServerStatus_CurrentTime
        self.set_variable_getter(Server_ServerStatus_CurrentTime, move |_, _, _| {
            Ok(Some(DataValue::new(DateTime::now())))
        });

        // State OPC UA Part 5 12.6, Valid states are
        //     State (Server_ServerStatus_State)
        self.set_variable_getter(Server_ServerStatus_State, move |_, _, _| {
            // let server_state =  trace_read_lock_unwrap!(server_state);
            Ok(Some(DataValue::new(0 as i32)))
        });

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
        self.register_method_handler(ObjectId::Server, MethodId::Server_GetMonitoredItems, Box::new(method_impls::handle_get_monitored_items));
        self.register_method_handler(ObjectId::Server, MethodId::Server_ResendData, Box::new(method_impls::handle_resend_data));
    }

    /// Returns the node id for the root folder
    pub fn root_folder_id() -> NodeId {
        ObjectId::RootFolder.into()
    }

    /// Returns the node id for the objects folder
    pub fn objects_folder_id() -> NodeId {
        ObjectId::ObjectsFolder.into()
    }

    /// Returns the node id for the types folder
    pub fn types_folder_id() -> NodeId {
        ObjectId::TypesFolder.into()
    }

    /// Returns the node id for the views folder
    pub fn views_folder_id() -> NodeId {
        ObjectId::ViewsFolder.into()
    }

    /// Returns the root folder
    pub fn root_folder(&self) -> &Object {
        expect_and_find_object!(self, &AddressSpace::root_folder_id())
    }

    /// Returns the objects folder
    pub fn objects_folder(&self) -> &Object {
        expect_and_find_object!(self, &AddressSpace::objects_folder_id())
    }

    /// Returns the types folder
    pub fn types_folder(&self) -> &Object {
        expect_and_find_object!(self, &AddressSpace::types_folder_id())
    }

    /// Returns the views folder
    pub fn views_folder(&self) -> &Object {
        expect_and_find_object!(self, &AddressSpace::views_folder_id())
    }

    /// Inserts a node into the address space node map and its references to other target nodes.
    /// The tuple of references is the target node id, reference type id and a bool which is false for
    /// a forward reference and indicating inverse
    pub fn insert<T>(&mut self, node: T, references: Option<&[(&NodeId, ReferenceTypeId, ReferenceDirection)]>) where T: Into<NodeType> {
        let node_type = node.into();
        let node_id = node_type.node_id();
        if self.node_exists(&node_id) {
            panic!("This node {:?} already exists", node_id);
        }
        self.node_map.insert(node_id.clone(), node_type);

        // If references are supplied, add them now
        if let Some(references) = references {
            self.references.insert(&node_id, references);
        }
        self.update_last_modified();
    }

    /// Adds the standard nodeset to the address space
    pub fn add_default_nodes(&mut self) {
        debug!("populating address space");

        // Reserve space in the maps. The default node set contains just under 2000 values for
        // nodes, references and inverse references.
        self.node_map.reserve(2000);

        // Run the generated code that will populate the address space with the default nodes
        super::generated::populate_address_space(self);
//        debug!("finished populating address space, number of nodes = {}, number of references = {}, number of reverse references = {}",
//               self.node_map.len(), self.references.len(), self.inverse_references.len());

        // Build up the map of subtypes
        self.references.build_reference_type_subtypes();
    }

    // Inserts a bunch of references between two nodes into the address space
    pub fn insert_references(&mut self, references: &[(&NodeId, &NodeId, ReferenceTypeId)]) {
        self.references.insert_references(references);
        self.update_last_modified();
    }

    /// Inserts a single reference between two nodes in the address space
    pub fn insert_reference(&mut self, node_id: &NodeId, target_node_id: &NodeId, reference_type_id: ReferenceTypeId) {
        self.insert_references(&[(node_id, target_node_id, reference_type_id)]);
    }

    pub fn set_node_type<T>(&mut self, node_id: &NodeId, node_type: T) where T: Into<NodeId> {
        self.insert_reference(node_id, &node_type.into(), ReferenceTypeId::HasTypeDefinition);
    }

    pub fn add_has_component(&mut self, node_id_from: &NodeId, node_id_to: &NodeId) {
        self.insert_reference(node_id_from, node_id_to, ReferenceTypeId::HasComponent);
    }

    pub fn add_organizes(&mut self, node_id_from: &NodeId, node_id_to: &NodeId) {
        self.insert_reference(node_id_from, node_id_to, ReferenceTypeId::Organizes);
    }

    pub fn add_has_child(&mut self, node_id_from: &NodeId, node_id_to: &NodeId) {
        self.insert_reference(node_id_from, node_id_to, ReferenceTypeId::HasChild);
    }

    pub fn add_has_property(&mut self, node_id_from: &NodeId, node_id_to: &NodeId) {
        self.insert_reference(node_id_from, node_id_to, ReferenceTypeId::HasProperty);
    }

    pub fn find_node(&self, node_id: &NodeId) -> Option<&NodeType> {
        self.node_map.get(node_id)
    }

    pub fn find_node_mut(&mut self, node_id: &NodeId) -> Option<&mut NodeType> {
        self.node_map.get_mut(node_id)
    }

    pub fn node_exists(&self, node_id: &NodeId) -> bool {
        self.node_map.contains_key(node_id)
    }

    /// Adds a node as a child (organized by) another node. The type id says what kind of node the object
    /// should be, e.g. folder node or something else.
    pub fn add_organized_node<R, S>(&mut self, node_id: &NodeId, browse_name: R, display_name: S, parent_node_id: &NodeId, node_type_id: ObjectTypeId) -> Result<NodeId, ()>
        where R: Into<QualifiedName>, S: Into<LocalizedText>
    {
        if self.node_exists(&node_id) {
            panic!("Node {:?} already exists", node_id);
        } else {
            // Add a relationship to the parent
            self.insert(Object::new(&node_id, browse_name, display_name, 0), Some(&[
                (&parent_node_id, ReferenceTypeId::Organizes, ReferenceDirection::Inverse),
                (&node_type_id.into(), ReferenceTypeId::HasTypeDefinition, ReferenceDirection::Forward),
            ]));
            Ok(node_id.clone())
        }
    }

    /// Adds a folder with a specified id
    pub fn add_folder_with_id<R, S>(&mut self, node_id: &NodeId, browse_name: R, display_name: S, parent_node_id: &NodeId) -> Result<NodeId, ()>
        where R: Into<QualifiedName>, S: Into<LocalizedText>
    {
        self.add_organized_node(node_id, browse_name, display_name, parent_node_id, ObjectTypeId::FolderType)
    }

    /// Adds a folder using a generated node id
    pub fn add_folder<R, S>(&mut self, browse_name: R, display_name: S, parent_node_id: &NodeId) -> Result<NodeId, ()>
        where R: Into<QualifiedName>, S: Into<LocalizedText>
    {
        self.add_folder_with_id(&NodeId::next_numeric(), browse_name, display_name, parent_node_id)
    }

    /// Adds a list of variables to the specified parent node
    pub fn add_variables(&mut self, variables: Vec<Variable>, parent_node_id: &NodeId) -> Vec<Result<NodeId, ()>> {
        let mut result = Vec::with_capacity(variables.len());
        for variable in variables {
            result.push(self.add_variable(variable, parent_node_id));
        }
        self.update_last_modified();
        result
    }

    /// Adds a single variable under the parent node
    pub fn add_variable(&mut self, variable: Variable, parent_node_id: &NodeId) -> Result<NodeId, ()> {
        let node_id = variable.node_id();
        if !self.node_map.contains_key(&node_id) {
            self.insert(NodeType::Variable(variable), Some(&[
                (&parent_node_id, ReferenceTypeId::Organizes, ReferenceDirection::Inverse),
            ]));
            Ok(node_id)
        } else {
            Err(())
        }
    }

    /// Deletes a node and optionally any references to / from it in the address space
    pub fn delete_node(&mut self, node_id: &NodeId, delete_target_references: bool) -> bool {
        let removed_node = self.node_map.remove(&node_id);
        let removed_target_references = if delete_target_references {
            self.references.delete_references_to_node(node_id)
        } else {
            false
        };
        removed_node.is_some() || removed_target_references
    }

    /// Finds the matching reference and deletes it
    pub fn delete_reference(&mut self, node_id: &NodeId, target_node_id: &NodeId, reference_type_id: ReferenceTypeId) -> bool {
        self.references.delete_reference(node_id, target_node_id, reference_type_id)
    }

    /// Find and return a variable with the specified node id or return None if it cannot be
    /// found or is not a variable
    pub fn find_variable<N>(&self, node_id: N) -> Option<&Variable> where N: Into<NodeId> {
        self.find_variable_by_ref(&node_id.into())
    }

    /// Find and return a variable with the specified node id or return None if it cannot be
    /// found or is not a variable
    pub fn find_variable_by_ref(&self, node_id: &NodeId) -> Option<&Variable> {
        if let Some(node) = self.node_map.get(node_id) {
            if let &NodeType::Variable(ref variable) = node {
                Some(variable)
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Find and return a variable with the specified node id or return None if it cannot be
    /// found or is not a variable
    pub fn find_variable_mut<N>(&mut self, node_id: N) -> Option<&mut Variable> where N: Into<NodeId> {
        self.find_variable_mut_by_ref(&node_id.into())
    }

    /// Find and return a variable with the specified node id or return None if it cannot be
    /// found or is not a variable
    pub fn find_variable_mut_by_ref(&mut self, node_id: &NodeId) -> Option<&mut Variable> {
        if let Some(node) = self.node_map.get_mut(node_id) {
            if let &mut NodeType::Variable(ref mut variable) = node {
                Some(variable)
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Set a variable value from its NodeId. The function will return false if the variable does
    /// not exist, or the node is not a variable.
    pub fn set_variable_value<N, V>(&mut self, node_id: N, value: V, source_timestamp: &DateTime, server_timestamp: &DateTime) -> bool
        where N: Into<NodeId>, V: Into<Variant> {
        self.set_variable_value_by_ref(&node_id.into(), value, source_timestamp, server_timestamp)
    }

    /// Set a variable value from its NodeId. The function will return false if the variable does
    /// not exist, or the node is not a variable.
    pub fn set_variable_value_by_ref<V>(&mut self, node_id: &NodeId, value: V, source_timestamp: &DateTime, server_timestamp: &DateTime) -> bool
        where V: Into<Variant> {
        if let Some(ref mut variable) = self.find_variable_mut_by_ref(node_id) {
            variable.set_value_direct(value, source_timestamp, server_timestamp);
            true
        } else {
            false
        }
    }

    /// Gets a variable value with the supplied NodeId. The function will return Err if the
    /// NodeId does not exist or is not a variable.
    pub fn get_variable_value<N>(&self, node_id: N) -> Result<DataValue, ()> where N: Into<NodeId> {
        self.find_variable(node_id)
            .map(|variable| variable.value())
            .ok_or_else(|| ())
    }

    /// Registers a method callback on the specified object id and method id
    pub fn register_method_handler<N1, N2>(&mut self, object_id: N1, method_id: N2, handler: MethodCallback) where N1: Into<NodeId>, N2: Into<NodeId> {
        // Check the object id and method id actually exist as things in the address space
        let object_id = object_id.into();
        let method_id = method_id.into();
        if !is_object!(self, &object_id) || !is_method!(self, &method_id) {
            panic!("Invalid id {:?} / {:?} supplied to method handler", object_id, method_id)
        }
        let key = MethodKey { object_id, method_id };
        if let Some(_) = self.method_handlers.insert(key, handler) {
            trace!("Registration replaced a previous callback");
        }
    }

    /// Test if the type definition is defined and valid for a class of the specified type.
    /// i.e. if we have a Variable or Object class that the type is a VariableType or ObjectType
    /// respectively.
    pub fn is_valid_type_definition(&self, node_class: NodeClass, type_definition: &NodeId) -> bool {
        match node_class {
            NodeClass::Object => {
                if type_definition.is_null() {
                    false
                } else {
                    if let Some(NodeType::ObjectType(_)) = self.find_node(type_definition) {
                        true
                    } else {
                        false
                    }
                }
            }
            NodeClass::Variable => {
                if type_definition.is_null() {
                    false
                } else {
                    if let Some(NodeType::VariableType(_)) = self.find_node(type_definition) {
                        true
                    } else {
                        false
                    }
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
    pub fn has_reference(&self, from_node_id: &NodeId, to_node_id: &NodeId, reference_type: ReferenceTypeId) -> bool {
        self.references.has_reference(from_node_id, to_node_id, reference_type)
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
    pub fn call_method(&self, server_state: &ServerState, session: &mut Session, request: &CallMethodRequest) -> Result<CallMethodResult, StatusCode> {
        let (object_id, method_id) = (&request.object_id, &request.method_id);

        // Handle the call
        if !is_object!(self, object_id) {
            error!("Method call to {:?} on {:?} but the node id is not recognized!", method_id, object_id);
            Err(StatusCode::BadNodeIdUnknown)
        } else if !is_method!(self, method_id) {
            error!("Method call to {:?} on {:?} but the method id is not recognized!", method_id, object_id);
            Err(StatusCode::BadMethodInvalid)
        } else if !self.method_exists_on_object(object_id, method_id) {
            error!("Method call to {:?} on {:?} but the method does not exist on the object!", method_id, object_id);
            Err(StatusCode::BadMethodInvalid)
        } else {
            // TODO check security - session / user may not have permission to call methods

            // Find the handler for this method call
            let key = MethodKey {
                object_id: object_id.clone(),
                method_id: method_id.clone(),
            };
            if let Some(handler) = self.method_handlers.get(&key) {
                // Call the handler
                trace!("Method call to {:?} on {:?} being handled by a registered handler", method_id, object_id);
                handler(self, server_state, session, request)
            } else {
                // TODO we could do a secondary search on a (NodeId::null(), method_id) here
                //  so that method handler is reusable for multiple objects
                error!("Method call to {:?} on {:?} has no handler, treating as invalid", method_id, object_id);
                Err(StatusCode::BadMethodInvalid)
            }
        }
    }

    /// Finds forward references from the specified node
    pub fn find_references_from(&self, node_id: &NodeId, reference_filter: Option<(ReferenceTypeId, bool)>) -> Option<Vec<Reference>> {
        self.references.find_references_from(node_id, reference_filter)
    }

    /// Finds inverse references, it those that point to the specified node
    pub fn find_references_to(&self, node_id: &NodeId, reference_filter: Option<(ReferenceTypeId, bool)>) -> Option<Vec<Reference>> {
        self.references.find_references_to(node_id, reference_filter)
    }

    /// Finds references for optionally forwards, inverse or both and return the references. The usize
    /// represents the index in the collection where the inverse references start (if applicable)
    pub fn find_references_by_direction(&self, node_id: &NodeId, browse_direction: BrowseDirection, reference_filter: Option<(ReferenceTypeId, bool)>) -> (Vec<Reference>, usize) {
        self.references.find_references_by_direction(node_id, browse_direction, reference_filter)
    }

    fn update_last_modified(&mut self) {
        self.last_modified = Utc::now();
    }
}