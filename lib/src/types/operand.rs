// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

use std::convert::TryFrom;

use crate::types::{
    attribute::AttributeId,
    node_ids::ObjectId,
    service_types::{
        AttributeOperand, ContentFilter, ContentFilterElement, ElementOperand, FilterOperator,
        LiteralOperand, SimpleAttributeOperand,
    },
    status_code::StatusCode,
    DecodingOptions, ExtensionObject, NodeId, QualifiedName, UAString, Variant,
};

#[derive(PartialEq)]
pub enum OperandType {
    ElementOperand,
    LiteralOperand,
    AttributeOperand,
    SimpleAttributeOperand,
}

pub enum Operand {
    ElementOperand(ElementOperand),
    LiteralOperand(LiteralOperand),
    AttributeOperand(AttributeOperand),
    SimpleAttributeOperand(SimpleAttributeOperand),
}

impl From<i8> for LiteralOperand {
    fn from(v: i8) -> Self {
        Self::from(Variant::from(v))
    }
}

impl From<u8> for LiteralOperand {
    fn from(v: u8) -> Self {
        Self::from(Variant::from(v))
    }
}

impl From<i16> for LiteralOperand {
    fn from(v: i16) -> Self {
        Self::from(Variant::from(v))
    }
}

impl From<u16> for LiteralOperand {
    fn from(v: u16) -> Self {
        Self::from(Variant::from(v))
    }
}

impl From<i32> for LiteralOperand {
    fn from(v: i32) -> Self {
        Self::from(Variant::from(v))
    }
}

impl From<u32> for LiteralOperand {
    fn from(v: u32) -> Self {
        Self::from(Variant::from(v))
    }
}

impl From<f32> for LiteralOperand {
    fn from(v: f32) -> Self {
        Self::from(Variant::from(v))
    }
}

impl From<f64> for LiteralOperand {
    fn from(v: f64) -> Self {
        Self::from(Variant::from(v))
    }
}

impl From<bool> for LiteralOperand {
    fn from(v: bool) -> Self {
        Self::from(Variant::from(v))
    }
}

impl From<&str> for LiteralOperand {
    fn from(v: &str) -> Self {
        Self::from(Variant::from(v))
    }
}

impl From<()> for LiteralOperand {
    fn from(_v: ()) -> Self {
        Self::from(Variant::from(()))
    }
}

impl From<Variant> for LiteralOperand {
    fn from(v: Variant) -> Self {
        LiteralOperand { value: v }
    }
}

impl TryFrom<&ExtensionObject> for Operand {
    type Error = StatusCode;

    fn try_from(v: &ExtensionObject) -> Result<Self, Self::Error> {
        let object_id = v
            .object_id()
            .map_err(|_| StatusCode::BadFilterOperandInvalid)?;
        let decoding_options = DecodingOptions::minimal();
        let operand = match object_id {
            ObjectId::ElementOperand_Encoding_DefaultBinary => {
                Operand::ElementOperand(v.decode_inner::<ElementOperand>(&decoding_options)?)
            }
            ObjectId::LiteralOperand_Encoding_DefaultBinary => {
                Operand::LiteralOperand(v.decode_inner::<LiteralOperand>(&decoding_options)?)
            }
            ObjectId::AttributeOperand_Encoding_DefaultBinary => {
                Operand::AttributeOperand(v.decode_inner::<AttributeOperand>(&decoding_options)?)
            }
            ObjectId::SimpleAttributeOperand_Encoding_DefaultBinary => {
                Operand::SimpleAttributeOperand(
                    v.decode_inner::<SimpleAttributeOperand>(&decoding_options)?,
                )
            }
            _ => {
                return Err(StatusCode::BadFilterOperandInvalid);
            }
        };
        Ok(operand)
    }
}

impl From<&Operand> for ExtensionObject {
    fn from(v: &Operand) -> Self {
        match v {
            Operand::ElementOperand(ref op) => {
                ExtensionObject::from_encodable(ObjectId::ElementOperand_Encoding_DefaultBinary, op)
            }
            Operand::LiteralOperand(ref op) => {
                ExtensionObject::from_encodable(ObjectId::LiteralOperand_Encoding_DefaultBinary, op)
            }
            Operand::AttributeOperand(ref op) => ExtensionObject::from_encodable(
                ObjectId::AttributeOperand_Encoding_DefaultBinary,
                op,
            ),
            Operand::SimpleAttributeOperand(ref op) => ExtensionObject::from_encodable(
                ObjectId::SimpleAttributeOperand_Encoding_DefaultBinary,
                op,
            ),
        }
    }
}

impl From<Operand> for ExtensionObject {
    fn from(v: Operand) -> Self {
        Self::from(&v)
    }
}

impl From<(FilterOperator, Vec<Operand>)> for ContentFilterElement {
    fn from(v: (FilterOperator, Vec<Operand>)) -> ContentFilterElement {
        ContentFilterElement {
            filter_operator: v.0,
            filter_operands: Some(v.1.iter().map(|op| op.into()).collect()),
        }
    }
}

impl From<ElementOperand> for Operand {
    fn from(v: ElementOperand) -> Operand {
        Operand::ElementOperand(v)
    }
}

impl From<LiteralOperand> for Operand {
    fn from(v: LiteralOperand) -> Self {
        Operand::LiteralOperand(v)
    }
}

impl From<SimpleAttributeOperand> for Operand {
    fn from(v: SimpleAttributeOperand) -> Self {
        Operand::SimpleAttributeOperand(v)
    }
}

impl Operand {
    pub fn element(index: u32) -> Operand {
        ElementOperand { index }.into()
    }

    pub fn literal<T>(literal: T) -> Operand
    where
        T: Into<LiteralOperand>,
    {
        Operand::LiteralOperand(literal.into())
    }

    /// Creates a simple attribute operand. The browse path is the browse name using / as a separator.
    pub fn simple_attribute<T>(
        type_definition_id: T,
        browse_path: &str,
        attribute_id: AttributeId,
        index_range: UAString,
    ) -> Operand
    where
        T: Into<NodeId>,
    {
        SimpleAttributeOperand::new(type_definition_id, browse_path, attribute_id, index_range)
            .into()
    }

    pub fn operand_type(&self) -> OperandType {
        match self {
            Operand::ElementOperand(_) => OperandType::ElementOperand,
            Operand::LiteralOperand(_) => OperandType::LiteralOperand,
            Operand::AttributeOperand(_) => OperandType::AttributeOperand,
            Operand::SimpleAttributeOperand(_) => OperandType::SimpleAttributeOperand,
        }
    }

    pub fn is_element(&self) -> bool {
        self.operand_type() == OperandType::ElementOperand
    }

    pub fn is_literal(&self) -> bool {
        self.operand_type() == OperandType::LiteralOperand
    }

    pub fn is_attribute(&self) -> bool {
        self.operand_type() == OperandType::AttributeOperand
    }

    pub fn is_simple_attribute(&self) -> bool {
        self.operand_type() == OperandType::SimpleAttributeOperand
    }
}

/// This is a convenience for building [`ContentFilter`] using operands as building blocks
/// This builder does not check to see that the content filter is valid, i.e. if you
/// reference an element by index that doesn't exist, or introduce a loop then you will
/// not get an error until you feed it to a server and the server rejects it or breaks.
///
/// The builder takes generic types to make it easier to work with. Operands are converted to
/// extension objects.
pub struct ContentFilterBuilder {
    elements: Vec<ContentFilterElement>,
}

impl Default for ContentFilterBuilder {
    fn default() -> Self {
        ContentFilterBuilder {
            elements: Vec::with_capacity(20),
        }
    }
}

impl ContentFilterBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    fn add_element(
        mut self,
        filter_operator: FilterOperator,
        filter_operands: Vec<Operand>,
    ) -> Self {
        let filter_operands = filter_operands.iter().map(ExtensionObject::from).collect();
        self.elements.push(ContentFilterElement {
            filter_operator,
            filter_operands: Some(filter_operands),
        });
        self
    }

    pub fn eq<T, S>(self, o1: T, o2: S) -> Self
    where
        T: Into<Operand>,
        S: Into<Operand>,
    {
        self.add_element(FilterOperator::Equals, vec![o1.into(), o2.into()])
    }

    pub fn null<T>(self, o1: T) -> Self
    where
        T: Into<Operand>,
    {
        self.add_element(FilterOperator::IsNull, vec![o1.into()])
    }

    pub fn gt<T, S>(self, o1: T, o2: S) -> Self
    where
        T: Into<Operand>,
        S: Into<Operand>,
    {
        self.add_element(FilterOperator::GreaterThan, vec![o1.into(), o2.into()])
    }

    pub fn lt<T, S>(self, o1: T, o2: S) -> Self
    where
        T: Into<Operand>,
        S: Into<Operand>,
    {
        self.add_element(FilterOperator::LessThan, vec![o1.into(), o2.into()])
    }

    pub fn gte<T, S>(self, o1: T, o2: S) -> Self
    where
        T: Into<Operand>,
        S: Into<Operand>,
    {
        self.add_element(
            FilterOperator::GreaterThanOrEqual,
            vec![o1.into(), o2.into()],
        )
    }

    pub fn lte<T, S>(self, o1: T, o2: S) -> Self
    where
        T: Into<Operand>,
        S: Into<Operand>,
    {
        self.add_element(FilterOperator::LessThanOrEqual, vec![o1.into(), o2.into()])
    }

    pub fn like<T, S>(self, o1: T, o2: S) -> Self
    where
        T: Into<Operand>,
        S: Into<Operand>,
    {
        self.add_element(FilterOperator::Like, vec![o1.into(), o2.into()])
    }

    pub fn not<T>(self, o1: T) -> Self
    where
        T: Into<Operand>,
    {
        self.add_element(FilterOperator::Not, vec![o1.into()])
    }

    pub fn between<T, S, U>(self, o1: T, o2: S, o3: U) -> Self
    where
        T: Into<Operand>,
        S: Into<Operand>,
        U: Into<Operand>,
    {
        self.add_element(
            FilterOperator::Between,
            vec![o1.into(), o2.into(), o3.into()],
        )
    }

    pub fn in_list<T, S>(self, o1: T, list_items: Vec<S>) -> Self
    where
        T: Into<Operand>,
        S: Into<Operand>,
    {
        // Make a list from the operand and then the items
        let mut filter_operands = Vec::with_capacity(list_items.len() + 1);
        filter_operands.push(o1.into());
        list_items.into_iter().for_each(|list_item| {
            filter_operands.push(list_item.into());
        });
        self.add_element(FilterOperator::InList, filter_operands)
    }

    pub fn and<T, S>(self, o1: T, o2: S) -> Self
    where
        T: Into<Operand>,
        S: Into<Operand>,
    {
        self.add_element(FilterOperator::And, vec![o1.into(), o2.into()])
    }

    pub fn or<T, S>(self, o1: T, o2: S) -> Self
    where
        T: Into<Operand>,
        S: Into<Operand>,
    {
        self.add_element(FilterOperator::Or, vec![o1.into(), o2.into()])
    }

    pub fn cast<T, S>(self, o1: T, o2: S) -> Self
    where
        T: Into<Operand>,
        S: Into<Operand>,
    {
        self.add_element(FilterOperator::Cast, vec![o1.into(), o2.into()])
    }

    pub fn bitwise_and<T, S>(self, o1: T, o2: S) -> Self
    where
        T: Into<Operand>,
        S: Into<Operand>,
    {
        self.add_element(FilterOperator::BitwiseAnd, vec![o1.into(), o2.into()])
    }

    pub fn bitwise_or<T, S>(self, o1: T, o2: S) -> Self
    where
        T: Into<Operand>,
        S: Into<Operand>,
    {
        self.add_element(FilterOperator::BitwiseOr, vec![o1.into(), o2.into()])
    }

    pub fn build(self) -> ContentFilter {
        ContentFilter {
            elements: Some(self.elements),
        }
    }
}

impl SimpleAttributeOperand {
    pub fn new<T>(
        type_definition_id: T,
        browse_path: &str,
        attribute_id: AttributeId,
        index_range: UAString,
    ) -> Self
    where
        T: Into<NodeId>,
    {
        // An improbable string to replace escaped forward slashes.
        const ESCAPE_PATTERN: &str = "###!!!###@@@$$$$";
        // Any escaped forward slashes will be replaced temporarily to allow split to work.
        let browse_path = browse_path.replace(r"\/", ESCAPE_PATTERN);
        // If we had a regex with look around support then we could split a pattern such as `r"(?<!\\)/"` where it
        // matches only if the pattern `/` isn't preceded by a backslash. Unfortunately the regex crate doesn't offer
        // this so an escaped forward slash is replaced with an improbable string instead.
        let browse_path = browse_path
            .split('/')
            .map(|s| QualifiedName::new(0, s.replace(ESCAPE_PATTERN, "/")))
            .collect();
        SimpleAttributeOperand {
            type_definition_id: type_definition_id.into(),
            browse_path: Some(browse_path),
            attribute_id: attribute_id as u32,
            index_range,
        }
    }
}
