//! Contains the implementation of `ObjectType` and `ObjectTypeBuilder`.

use opcua_types::service_types::ObjectTypeAttributes;

use crate::address_space::{base::Base, node::Node, node::NodeAttributes};

node_builder_impl!(ObjectTypeBuilder, ObjectType);

impl ObjectTypeBuilder {
    pub fn is_abstract(mut self, is_abstract: bool) -> Self {
        self.node.set_is_abstract(is_abstract);
        self
    }

    pub fn component_of<T>(self, component_of_id: T) -> Self where T: Into<NodeId> {
        self.reference(component_of_id, ReferenceTypeId::HasComponent, ReferenceDirection::Inverse)
    }

    pub fn has_component<T>(self, has_component_id: T) -> Self where T: Into<NodeId> {
        self.reference(has_component_id, ReferenceTypeId::HasComponent, ReferenceDirection::Forward)
    }

    pub fn property_of<T>(self, property_of_id: T) -> Self where T: Into<NodeId> {
        self.reference(property_of_id, ReferenceTypeId::HasProperty, ReferenceDirection::Inverse)
    }

    pub fn has_property<T>(self, has_property_id: T) -> Self where T: Into<NodeId> {
        self.reference(has_property_id, ReferenceTypeId::HasProperty, ReferenceDirection::Forward)
    }

    pub fn subtype_of<T>(self, type_id: T) -> Self where T: Into<NodeId> {
        self.reference(type_id, ReferenceTypeId::HasSubtype, ReferenceDirection::Inverse)
    }

    pub fn has_subtype<T>(self, subtype_id: T) -> Self where T: Into<NodeId> {
        self.reference(subtype_id, ReferenceTypeId::HasSubtype, ReferenceDirection::Forward)
    }
}

/// An `ObjectType` is a type of node within the `AddressSpace`.
#[derive(Debug)]
pub struct ObjectType {
    base: Base,
    is_abstract: bool,
}

node_impl!(ObjectType);

impl NodeAttributes for ObjectType {
    fn get_attribute(&self, attribute_id: AttributeId, max_age: f64) -> Option<DataValue> {
        self.base.get_attribute(attribute_id, max_age).or_else(|| {
            match attribute_id {
                AttributeId::IsAbstract => Some(Variant::from(self.is_abstract())),
                _ => None
            }.map(|v| v.into())
        })
    }

    fn set_attribute(&mut self, attribute_id: AttributeId, value: Variant) -> Result<(), StatusCode> {
        if let Some(value) = self.base.set_attribute(attribute_id, value)? {
            match attribute_id {
                AttributeId::IsAbstract => {
                    if let Variant::Boolean(v) = value {
                        self.set_is_abstract(v);
                        Ok(())
                    } else {
                        Err(StatusCode::BadTypeMismatch)
                    }
                }
                _ => Err(StatusCode::BadAttributeIdInvalid)
            }
        } else {
            Ok(())
        }
    }
}

impl Default for ObjectType {
    fn default() -> Self {
        Self {
            base: Base::new(NodeClass::ObjectType, &NodeId::null(), "", ""),
            is_abstract: false,
        }
    }
}

impl ObjectType {
    pub fn new<R, S>(node_id: &NodeId, browse_name: R, display_name: S, is_abstract: bool) -> ObjectType
        where R: Into<QualifiedName>,
              S: Into<LocalizedText>,
    {
        ObjectType {
            base: Base::new(NodeClass::ObjectType, node_id, browse_name, display_name),
            is_abstract,
        }
    }

    pub fn from_attributes<S>(node_id: &NodeId, browse_name: S, attributes: ObjectTypeAttributes) -> Result<Self, ()>
        where S: Into<QualifiedName>
    {
        let mandatory_attributes = AttributesMask::DISPLAY_NAME | AttributesMask::IS_ABSTRACT;
        let mask = AttributesMask::from_bits(attributes.specified_attributes).ok_or(())?;
        if mask.contains(mandatory_attributes) {
            let mut node = Self::new(node_id, browse_name, attributes.display_name, attributes.is_abstract);
            if mask.contains(AttributesMask::DESCRIPTION) {
                node.set_description(attributes.description);
            }
            if mask.contains(AttributesMask::WRITE_MASK) {
                node.set_write_mask(WriteMask::from_bits_truncate(attributes.write_mask));
            }
            if mask.contains(AttributesMask::USER_WRITE_MASK) {
                node.set_user_write_mask(WriteMask::from_bits_truncate(attributes.user_write_mask));
            }
            Ok(node)
        } else {
            error!("ObjectType cannot be created from attributes - missing mandatory values");
            Err(())
        }
    }

    pub fn is_valid(&self) -> bool {
        self.base.is_valid()
    }

    pub fn is_abstract(&self) -> bool {
        self.is_abstract
    }

    pub fn set_is_abstract(&mut self, is_abstract: bool) {
        self.is_abstract = is_abstract;
    }
}