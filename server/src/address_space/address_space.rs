use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

use chrono::Utc;

use opcua_types::*;
use opcua_types::node_ids::*;
use opcua_types::service_types::{BrowseDirection, RelativePath, RelativePathElement, ServerDiagnosticsSummaryDataType};
use opcua_types::status_codes::StatusCode;
use opcua_types::status_codes::StatusCode::*;
use opcua_types::service_types::{CallMethodRequest, CallMethodResult};

use address_space::AttrFnGetter;
use address_space::node::{Node, NodeType};
use address_space::object::Object;
use address_space::variable::Variable;
use address_space::method_impls;

use state::ServerState;
use session::Session;
use constants;
use DateTimeUtc;

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

/// The `NodeId` is the target node. The reference is held in a list by the source node.
/// The target node does not need to exist.
#[derive(Debug, Clone)]
pub struct Reference {
    pub reference_type_id: ReferenceTypeId,
    pub node_id: NodeId,
}

impl Reference {
    pub fn new(reference_type_id: ReferenceTypeId, node_id: &NodeId) -> Reference {
        Reference {
            reference_type_id: reference_type_id,
            node_id: node_id.clone(),
        }
    }
}

type MethodCallback = Box<Fn(&AddressSpace, &ServerState, &Session, &CallMethodRequest) -> Result<CallMethodResult, StatusCode> + Send + Sync + 'static>;

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
    /// A map of references between nodes
    references: HashMap<NodeId, Vec<Reference>>,
    /// A map of inverse references between nodes
    inverse_references: HashMap<NodeId, Vec<Reference>>,
    /// This is the last time that references to nodes were added or removed from the address space.
    last_modified: DateTimeUtc,
    /// Method handlers
    method_handlers: HashMap<MethodKey, MethodCallback>,
}

impl AddressSpace {
    /// Constructs a default address space. That consists of all the nodes in the implementation's
    /// supported profile.
    pub fn new() -> AddressSpace {
        // Construct the Root folder and the top level nodes
        let mut address_space = AddressSpace {
            node_map: HashMap::new(),
            references: HashMap::new(),
            inverse_references: HashMap::new(),
            last_modified: Utc::now(),
            method_handlers: HashMap::new(),
        };
        address_space.add_default_nodes();
        address_space
    }

    /// Returns the last modified date for the address space
    pub fn last_modified(&self) -> DateTimeUtc {
        self.last_modified.clone()
    }

    /// Sets values for nodes representing the server.
    pub fn set_server_state(&mut self, server_state: Arc<RwLock<ServerState>>) {
        use opcua_types::node_ids::VariableId::*;

        // Server variables
        {
            let server_state = trace_read_lock_unwrap!(server_state);
            if let Some(ref mut v) = self.find_variable_by_variable_id(Server_NamespaceArray) {
                v.set_value_direct(&DateTime::now(), Variant::new_string_array(&server_state.namespaces));
                v.set_array_dimensions(&[server_state.namespaces.len() as UInt32]);
            }
            if let Some(ref mut v) = self.find_variable_by_variable_id(Server_ServerArray) {
                v.set_value_direct(&DateTime::now(), Variant::new_string_array(&server_state.servers));
                v.set_array_dimensions(&[server_state.servers.len() as UInt32]);
            }
        }

        // ServerCapabilities
        {
            let server_state = trace_read_lock_unwrap!(server_state);
            let server_config = trace_read_lock_unwrap!(server_state.config);
            self.set_value_by_variable_id(Server_ServerCapabilities_MaxArrayLength, Variant::UInt32(server_config.max_array_length));
            self.set_value_by_variable_id(Server_ServerCapabilities_MaxStringLength, Variant::UInt32(server_config.max_string_length));
            self.set_value_by_variable_id(Server_ServerCapabilities_MaxByteStringLength, Variant::UInt32(server_config.max_byte_string_length));
            self.set_value_by_variable_id(Server_ServerCapabilities_MaxBrowseContinuationPoints, Variant::UInt32(constants::MAX_BROWSE_CONTINUATION_POINTS as UInt32));
            self.set_value_by_variable_id(Server_ServerCapabilities_MaxHistoryContinuationPoints, Variant::UInt32(constants::MAX_HISTORY_CONTINUATION_POINTS as UInt32));
            self.set_value_by_variable_id(Server_ServerCapabilities_MaxQueryContinuationPoints, Variant::UInt32(constants::MAX_QUERY_CONTINUATION_POINTS as UInt32));
            self.set_value_by_variable_id(Server_ServerCapabilities_MinSupportedSampleRate, Variant::Double(constants::MIN_SAMPLING_INTERVAL));
        }

        // Server_ServerCapabilities_ServerProfileArray
        if let Some(ref mut v) = self.find_variable_by_variable_id(Server_ServerCapabilities_ServerProfileArray) {
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
                "http://opcfoundation.org/UA-Profile/Server/Behaviour".to_string(),
                // Embedded UA server
                //  Micro Embedded Device Server Profile
                //  SecurityPolicy - Basic128Rsa15
                //  Standard DataChange Subscription Server Facet
                //  User Token - X509 Certificate Server Facet
                //  -Base Info Engineering Units
                //  -Base Info PLaceholder Modelling Rules
                //  -Base Info Type System
                //  Security Default ApplicationInstanceCertificate
                "http://opcfoundation.org/UA-Profile/Server/EmbeddedUA".to_string(),
            ];
            v.set_value_direct(&DateTime::now(), Variant::new_string_array(&server_profiles));
            v.set_array_dimensions(&[server_profiles.len() as UInt32]);
        }

        // Server_ServerCapabilities_LocaleIdArray
        // Server_ServerCapabilities_MinSupportedSampleRate

        // Server_ServerDiagnostics_ServerDiagnosticsSummary
        self.set_server_diagnostics_summary(ServerDiagnosticsSummaryDataType {
            server_view_count: 0,
            current_session_count: 0,
            cumulated_session_count: 0,
            security_rejected_session_count: 0,
            rejected_session_count: 0,
            session_timeout_count: 0,
            session_abort_count: 0,
            current_subscription_count: 0,
            cumulated_subscription_count: 0,
            publishing_interval_count: 0,
            security_rejected_requests_count: 0,
            rejected_requests_count: 0,
        });

        // Server_ServerDiagnostics_SamplingIntervalDiagnosticsArray
        // Server_ServerDiagnostics_SubscriptionDiagnosticsArray
        // Server_ServerDiagnostics_EnabledFlag

        // ServiceLevel - 0-255 worst to best quality of service
        self.set_value_by_variable_id(Server_ServiceLevel, Variant::Byte(255));

        // Auditing - var
        // ServerDiagnostics
        // VendorServiceInfo
        // ServerRedundancy

        // Server status
        self.set_value_by_variable_id(Server_ServerStatus_StartTime, Variant::DateTime(DateTime::now()));

        // Server_ServerStatus_CurrentTime
        if let Some(ref mut v) = self.find_variable_by_variable_id(Server_ServerStatus_CurrentTime) {
            // Used to return the current time of the server, i.e. now
            let getter = AttrFnGetter::new(move |_: NodeId, _: AttributeId| -> Result<Option<DataValue>, StatusCode> {
                Ok(Some(DataValue::new(DateTime::now())))
            });
            // Put a getter onto this thing so it can fetch the current time on demand
            v.set_value_getter(Arc::new(Mutex::new(getter)));
        }

        // State OPC UA Part 5 12.6, Valid states are
        //     State (Server_ServerStatus_State)
        if let Some(ref mut v) = self.find_variable_by_variable_id(Server_ServerStatus_State) {
            let _server_state = server_state.clone();
            // Used to return the current time of the server, i.e. now
            let getter = AttrFnGetter::new(move |_: NodeId, _: AttributeId| -> Result<Option<DataValue>, StatusCode> {
                // let server_state =  trace_read_lock_unwrap!(server_state);
                Ok(Some(DataValue::new(0 as Int32)))
            });
            v.set_value_getter(Arc::new(Mutex::new(getter)));
        }

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

        let server_object_id: NodeId = ObjectId::Server.into();
        self.register_method_handler(&server_object_id, &MethodId::Server_GetMonitoredItems.into(), Box::new(method_impls::handle_get_monitored_items));
    }

    /// Updates the server diagnostics data with new values
    pub fn set_server_diagnostics_summary(&mut self, sds: ServerDiagnosticsSummaryDataType) {
        use opcua_types::node_ids::VariableId::*;
        self.set_value_by_variable_id(Server_ServerDiagnostics_ServerDiagnosticsSummary_ServerViewCount, Variant::UInt32(sds.server_view_count));
        self.set_value_by_variable_id(Server_ServerDiagnostics_ServerDiagnosticsSummary_CurrentSessionCount, Variant::UInt32(sds.current_session_count));
        self.set_value_by_variable_id(Server_ServerDiagnostics_ServerDiagnosticsSummary_CumulatedSessionCount, Variant::UInt32(sds.cumulated_session_count));
        self.set_value_by_variable_id(Server_ServerDiagnostics_ServerDiagnosticsSummary_SecurityRejectedSessionCount, Variant::UInt32(sds.security_rejected_session_count));
        self.set_value_by_variable_id(Server_ServerDiagnostics_ServerDiagnosticsSummary_SessionTimeoutCount, Variant::UInt32(sds.session_timeout_count));
        self.set_value_by_variable_id(Server_ServerDiagnostics_ServerDiagnosticsSummary_SessionAbortCount, Variant::UInt32(sds.session_abort_count));
        self.set_value_by_variable_id(Server_ServerDiagnostics_ServerDiagnosticsSummary_PublishingIntervalCount, Variant::UInt32(sds.publishing_interval_count));
        self.set_value_by_variable_id(Server_ServerDiagnostics_ServerDiagnosticsSummary_CurrentSubscriptionCount, Variant::UInt32(sds.current_subscription_count));
        self.set_value_by_variable_id(Server_ServerDiagnostics_ServerDiagnosticsSummary_CumulatedSubscriptionCount, Variant::UInt32(sds.cumulated_subscription_count));
        self.set_value_by_variable_id(Server_ServerDiagnostics_ServerDiagnosticsSummary_SecurityRejectedRequestsCount, Variant::UInt32(sds.security_rejected_requests_count));
        self.set_value_by_variable_id(Server_ServerDiagnostics_ServerDiagnosticsSummary_RejectedRequestsCount, Variant::UInt32(sds.rejected_requests_count));
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

    /// Inserts a node into the address space node map
    pub fn insert<T>(&mut self, node: T) where T: 'static + Into<NodeType> {
        let node_type = node.into();
        let node_id = node_type.node_id();
        if self.node_exists(&node_id) {
            panic!("This node {:?} already exists", node_id);
        }
        self.node_map.insert(node_id, node_type);
        self.update_last_modified();
    }

    pub fn node_exists(&self, node_id: &NodeId) -> bool {
        self.node_map.contains_key(node_id)
    }

    pub fn find_nodes_relative_path(&self, node_id: &NodeId, relative_path: &RelativePath) -> Result<Vec<NodeId>, StatusCode> {
        if self.find_node(node_id).is_none() {
            return Err(BadNodeIdUnknown);
        }

        let relative_path_elements = relative_path.elements.as_ref().unwrap();
        if relative_path_elements.is_empty() {
            return Err(BadNothingToDo);
        }

        let mut matching_nodes = vec![node_id.clone()];
        let mut next_matching_nodes = Vec::with_capacity(100);

        // Traverse the relative path elements
        for relative_path_element in relative_path_elements.iter() {
            next_matching_nodes.clear();

            if matching_nodes.is_empty() {
                break;
            }

            for node_id in &matching_nodes {
                // Iterate current set of nodes and put the results into next
                if let Some(mut result) = self.follow_relative_path(&node_id, relative_path_element) {
                    next_matching_nodes.append(&mut result);
                }
            }

            matching_nodes.clear();
            matching_nodes.append(&mut next_matching_nodes);
        }

        Ok(matching_nodes)
    }

    fn follow_relative_path(&self, node_id: &NodeId, relative_path: &RelativePathElement) -> Option<Vec<NodeId>> {
        let reference_type_id = relative_path.reference_type_id.as_reference_type_id().unwrap();
        let reference_filter = Some((reference_type_id, relative_path.include_subtypes));
        let references = if relative_path.is_inverse {
            self.find_references_to(node_id, reference_filter)
        } else {
            self.find_references_from(node_id, reference_filter)
        };
        if let Some(references) = references {
            let compare_target_name = !relative_path.target_name.is_null();
            let mut result = Vec::with_capacity(references.len());
            for reference in &references {
                if let Some(node) = self.find_node(&reference.node_id) {
                    let node = node.as_node();
                    if !compare_target_name || node.browse_name() == relative_path.target_name {
                        result.push(reference.node_id.clone());
                    }
                }
            }
            Some(result)
        } else {
            None
        }
    }

    /// Adds a node as a child (organized by) another node. The type id says what kind of node the object
    /// should be, e.g. folder node or something else.
    pub fn add_organized_node(&mut self, node_id: &NodeId, browse_name: &str, display_name: &str, parent_node_id: &NodeId, node_type_id: ObjectTypeId) -> Result<NodeId, ()> {
        if self.node_exists(&node_id) {
            panic!("Node {:?} already exists", node_id);
        } else {
            // Add a relationship to the parent
            self.insert(Object::new(&node_id, browse_name, display_name, ""));
            self.add_organizes(&parent_node_id, &node_id);
            self.insert_reference(&node_id, &node_type_id.into(), ReferenceTypeId::HasTypeDefinition);
            self.update_last_modified();
            Ok(node_id.clone())
        }
    }

    /// Adds a folder with a specified id
    pub fn add_folder_with_id(&mut self, node_id: &NodeId, browse_name: &str, display_name: &str, parent_node_id: &NodeId) -> Result<NodeId, ()> {
        self.add_organized_node(node_id, browse_name, display_name, parent_node_id, ObjectTypeId::FolderType)
    }

    /// Adds a folder using a generated node id
    pub fn add_folder(&mut self, browse_name: &str, display_name: &str, parent_node_id: &NodeId) -> Result<NodeId, ()> {
        self.add_folder_with_id(&NodeId::next_numeric(), browse_name, display_name, parent_node_id)
    }

    /// Adds a list of varables to the specified parent node
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
            self.add_organizes(&parent_node_id, &node_id);
            self.insert(NodeType::Variable(variable));
            self.update_last_modified();
            Ok(node_id)
        } else {
            Err(())
        }
    }

    /// Adds a reference between one node and a target
    fn add_reference(reference_map: &mut HashMap<NodeId, Vec<Reference>>, node_id: &NodeId, reference: Reference) {
        if reference_map.contains_key(node_id) {
            let references = reference_map.get_mut(node_id).unwrap();
            references.push(reference);
        } else {
            // Some nodes will have more than one reference, so save some reallocs by reserving
            // space for some more.
            let mut references = Vec::with_capacity(8);
            references.push(reference);
            reference_map.insert(node_id.clone(), references);
        }
    }

    /// Find and return a variable with the specified node id or return None if it cannot be
    /// found or is not a variable
    pub fn find_variable_by_node_id(&mut self, node_id: &NodeId) -> Option<&mut Variable> {
        if let Some(node) = self.find_node_mut(node_id) {
            if let &mut NodeType::Variable(ref mut variable) = node {
                Some(variable)
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Find and return a variable with the specified variable id
    pub fn find_variable_by_variable_id(&mut self, variable_id: VariableId) -> Option<&mut Variable> {
        self.find_variable_by_node_id(&variable_id.into())
    }

    /// Set a variable value
    pub fn set_value_by_node_id(&mut self, node_id: &NodeId, value: Variant) -> bool {
        if let Some(ref mut variable) = self.find_variable_by_node_id(node_id) {
            variable.set_value_direct(&DateTime::now(), value);
            true
        } else {
            false
        }
    }

    /// This is a convenience method. It sets a value directly on a variable assuming the supplied
    /// node id exists in the address space and is a Variable node. The response is true if the
    /// value was set and false otherwise.
    pub fn set_value_by_variable_id(&mut self, variable_id: VariableId, value: Variant) -> bool {
        self.set_value_by_node_id(&variable_id.into(), value)
    }

    /// Registers a method callback on the specified object id and method id
    pub fn register_method_handler(&mut self, object_id: &NodeId, method_id: &NodeId, handler: MethodCallback) {
        // Check the object id and method id actually exist as things in the address space
        if !is_object!(self, object_id) || !is_method!(self, method_id) {
            panic!("Invalid id {:?} / {:?} supplied to method handler", object_id, method_id)
        }
        let key = MethodKey {
            object_id: object_id.clone(),
            method_id: method_id.clone(),
        };
        if let Some(_) = self.method_handlers.insert(key, handler) {
            trace!("Registration replaced a previous callback");
        }
    }

    /// This finds the type definition (if any corresponding to the input object)
    fn get_type_id(&self, node_id: &NodeId) -> Option<NodeId> {
        if let Some(references) = self.references.get(&node_id) {
            if let Some(reference) = references.iter().find(|r| {
                r.reference_type_id == ReferenceTypeId::HasTypeDefinition
            }) {
                Some(reference.node_id.clone())
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Test if a reference relationship exists between one node and another node
    fn has_reference(&self, from_node_id: &NodeId, reference_type: ReferenceTypeId, to_node_id: &NodeId) -> bool {
        if let Some(references) = self.references.get(&from_node_id) {
            references.iter().find(|r| {
                r.reference_type_id == reference_type && r.node_id == *to_node_id
            }).is_some()
        } else {
            false
        }
    }

    /// Tests if a method exists on a specific object. This will be true if the method id is
    /// a HasComponent of the object itself, or a HasComponent of the object type
    fn method_exists_on_object(&self, object_id: &NodeId, method_id: &NodeId) -> bool {
        // Look for the method first on the object id, else on the object's type
        if self.has_reference(object_id, ReferenceTypeId::HasComponent, method_id) {
            true
        } else if let Some(object_type_id) = self.get_type_id(&object_id) {
            self.has_reference(&object_type_id, ReferenceTypeId::HasComponent, method_id)
        } else {
            error!("Method call to {:?} on {:?} but the method id is not on the object or its object type!", method_id, object_id);
            false
        }
    }

    /// Calls a method node with the supplied request and expecting a result.
    ///
    /// Calls require a registered handler to handle the method. If there is no handler, or if
    /// the request refers to a non existent object / method, the function will return an error.
    pub fn call_method(&self, server_state: &ServerState, session: &Session, request: &CallMethodRequest) -> Result<CallMethodResult, StatusCode> {
        let (object_id, method_id) = (&request.object_id, &request.method_id);

        // Handle the call
        if !is_object!(self, object_id) {
            error!("Method call to {:?} on {:?} but the node id is not recognized!", method_id, object_id);
            Err(BadNodeIdUnknown)
        } else if !is_method!(self, method_id) {
            error!("Method call to {:?} on {:?} but the method id is not recognized!", method_id, object_id);
            Err(BadMethodInvalid)
        } else if !self.method_exists_on_object(object_id, method_id) {
            error!("Method call to {:?} on {:?} but the method does not exist on the object!", method_id, object_id);
            Err(BadMethodInvalid)
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
                // so that method handler is reusable for multiple objects
                error!("Method call to {:?} on {:?} has no handler, treating as invalid", method_id, object_id);
                Err(BadMethodInvalid)
            }
        }
    }

    fn reference_type_matches(&self, r1: ReferenceTypeId, r2: ReferenceTypeId, include_subtypes: bool) -> bool {
        if r1 == r2 {
            true
        } else if include_subtypes {
            // THIS IS AN UGLY HACK. The subtype code should really walk down the hierarchy of
            // types in the address space to figure this out
            match r1 {
                ReferenceTypeId::HierarchicalReferences => {
                    match r2 {
                        ReferenceTypeId::HierarchicalReferences | ReferenceTypeId::HasChild |
                        ReferenceTypeId::HasSubtype | ReferenceTypeId::Organizes |
                        ReferenceTypeId::Aggregates | ReferenceTypeId::HasProperty |
                        ReferenceTypeId::HasComponent | ReferenceTypeId::HasOrderedComponent |
                        ReferenceTypeId::HasEventSource | ReferenceTypeId::HasNotifier => {
                            true
                        }
                        _ => false
                    }
                }
                ReferenceTypeId::HasChild => {
                    match r2 {
                        ReferenceTypeId::Aggregates | ReferenceTypeId::HasComponent |
                        ReferenceTypeId::HasHistoricalConfiguration | ReferenceTypeId::HasProperty |
                        ReferenceTypeId::HasOrderedComponent | ReferenceTypeId::HasSubtype => {
                            true
                        }
                        _ => false
                    }
                }
                ReferenceTypeId::Aggregates => {
                    match r2 {
                        ReferenceTypeId::HasComponent | ReferenceTypeId::HasHistoricalConfiguration |
                        ReferenceTypeId::HasProperty | ReferenceTypeId::HasOrderedComponent => {
                            true
                        }
                        _ => false
                    }
                }
                ReferenceTypeId::HasComponent => {
                    r2 == ReferenceTypeId::HasOrderedComponent
                }
                ReferenceTypeId::HasEventSource => {
                    r2 == ReferenceTypeId::HasNotifier
                }
                _ => {
                    // TODO somehow work out subtypes, e.g. working back along inverse references
                    false
                }
            }
        } else {
            false
        }
    }

    fn filter_references_by_type(&self, references: &Vec<Reference>, reference_filter: Option<(ReferenceTypeId, bool)>) -> Vec<Reference> {
        if reference_filter.is_none() {
            references.clone()
        } else {
            // Filter by type
            let (reference_type_id, include_subtypes) = reference_filter.unwrap();
            let mut result = Vec::new();
            for reference in references {
                if self.reference_type_matches(reference_type_id, reference.reference_type_id, include_subtypes) {
                    result.push(reference.clone());
                }
            }
            result
        }
    }

    /// Find and filter references that refer to the specified node.
    fn find_references(&self, reference_map: &HashMap<NodeId, Vec<Reference>>, node_id: &NodeId, reference_filter: Option<(ReferenceTypeId, bool)>) -> Option<Vec<Reference>> {
        if let Some(ref node_references) = reference_map.get(node_id) {
            let result = self.filter_references_by_type(node_references, reference_filter);
            if result.is_empty() {
                None
            } else {
                Some(result)
            }
        } else {
            None
        }
    }

    /// Finds forward references from the specified node
    pub fn find_references_from(&self, node_id: &NodeId, reference_filter: Option<(ReferenceTypeId, bool)>) -> Option<Vec<Reference>> {
        self.find_references(&self.references, node_id, reference_filter)
    }

    /// Finds inverse references, it those that point to the specified node
    pub fn find_references_to(&self, node_id: &NodeId, reference_filter: Option<(ReferenceTypeId, bool)>) -> Option<Vec<Reference>> {
        self.find_references(&self.inverse_references, node_id, reference_filter)
    }

    /// Finds references for optionally forwards, inverse or both and return the references. The usize
    /// represents the index in the collection where the inverse references start (if applicable)
    pub fn find_references_by_direction(&self, node_id: &NodeId, browse_direction: BrowseDirection, reference_filter: Option<(ReferenceTypeId, bool)>) -> (Vec<Reference>, usize) {
        let mut references = Vec::new();
        let inverse_ref_idx: usize;
        match browse_direction {
            BrowseDirection::Forward => {
                if let Some(mut forward_references) = self.find_references_from(node_id, reference_filter) {
                    references.append(&mut forward_references);
                }
                inverse_ref_idx = references.len();
            }
            BrowseDirection::Inverse => {
                inverse_ref_idx = 0;
                if let Some(mut inverse_references) = self.find_references_to(node_id, reference_filter) {
                    references.append(&mut inverse_references);
                }
            }
            BrowseDirection::Both => {
                if let Some(mut forward_references) = self.find_references_from(node_id, reference_filter) {
                    references.append(&mut forward_references);
                }
                inverse_ref_idx = references.len();
                if let Some(mut inverse_references) = self.find_references_to(node_id, reference_filter) {
                    references.append(&mut inverse_references);
                }
            }
        }
        (references, inverse_ref_idx)
    }

    fn update_last_modified(&mut self) {
        self.last_modified = Utc::now();
    }

    /// Adds the standard nodeset to the address space
    pub fn add_default_nodes(&mut self) {
        debug!("populating address space");

        // Reserve space in the maps. The default node set contains just under 2000 values for
        // nodes, references and inverse references.
        self.node_map.reserve(2000);
        self.references.reserve(2000);
        self.inverse_references.reserve(2000);

        // Run the generated code that will populate the address space with the default nodes
        super::generated::populate_address_space(self);
        debug!("finished populating address space, number of nodes = {}, number of references = {}, number of reverse references = {}",
               self.node_map.len(), self.references.len(), self.inverse_references.len());
    }

    // Inserts a bunch of references between two nodes into the address space
    pub fn insert_references(&mut self, references: &[(&NodeId, &NodeId, ReferenceTypeId)]) {
        references.iter().for_each(|reference| {
            let (node_id_from, node_id_to, reference_type_id) = *reference;
            if node_id_from == node_id_to {
                panic!("Node id from == node id to {:?}", node_id_from);
            }
            AddressSpace::add_reference(&mut self.references, node_id_from, Reference::new(reference_type_id, node_id_to));
            AddressSpace::add_reference(&mut self.inverse_references, node_id_to, Reference::new(reference_type_id, node_id_from));
        });
        self.update_last_modified();
    }

    /// Inserts a single reference between two nodes in the address space
    pub fn insert_reference(&mut self, node_id_from: &NodeId, node_id_to: &NodeId, reference_type_id: ReferenceTypeId) {
        self.insert_references(&[(node_id_from, node_id_to, reference_type_id)]);
    }

    pub fn set_object_type(&mut self, node_id: &NodeId, object_type: ObjectTypeId) {
        self.insert_reference(node_id, &object_type.into(), ReferenceTypeId::HasTypeDefinition);
    }

    pub fn set_variable_type(&mut self, node_id: &NodeId, variable_type: VariableTypeId) {
        self.insert_reference(node_id, &variable_type.into(), ReferenceTypeId::HasTypeDefinition);
    }

    pub fn set_variable_as_property_type(&mut self, node_id: &NodeId) {
        self.set_variable_type(node_id, VariableTypeId::PropertyType);
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
}