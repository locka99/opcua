use super::{
    encoding::DecodingOptions,
    extension_object::ExtensionObject,
    node_ids::ObjectId,
    service_types::{
        DataTypeAttributes, GenericAttributes, MethodAttributes, ObjectAttributes,
        ObjectTypeAttributes, ReferenceTypeAttributes, VariableAttributes, VariableTypeAttributes,
        ViewAttributes,
    },
    status_code::StatusCode,
};

#[derive(Clone, Debug)]
pub enum AddNodeAttributes {
    Object(ObjectAttributes),
    Variable(VariableAttributes),
    Method(MethodAttributes),
    ObjectType(ObjectTypeAttributes),
    VariableType(VariableTypeAttributes),
    ReferenceType(ReferenceTypeAttributes),
    DataType(DataTypeAttributes),
    View(ViewAttributes),
    Generic(GenericAttributes),
    None,
}

impl AddNodeAttributes {
    pub fn from_extension_object(
        obj: ExtensionObject,
        options: &DecodingOptions,
    ) -> Result<Self, StatusCode> {
        if obj.is_null() {
            return Ok(Self::None);
        }
        match obj
            .object_id()
            .map_err(|_| StatusCode::BadNodeAttributesInvalid)?
        {
            ObjectId::ObjectAttributes_Encoding_DefaultBinary => {
                Ok(Self::Object(obj.decode_inner(options)?))
            }
            ObjectId::VariableAttributes_Encoding_DefaultBinary => {
                Ok(Self::Variable(obj.decode_inner(options)?))
            }
            ObjectId::MethodAttributes_Encoding_DefaultBinary => {
                Ok(Self::Method(obj.decode_inner(options)?))
            }
            ObjectId::ObjectTypeAttributes_Encoding_DefaultBinary => {
                Ok(Self::ObjectType(obj.decode_inner(options)?))
            }
            ObjectId::VariableTypeAttributes_Encoding_DefaultBinary => {
                Ok(Self::VariableType(obj.decode_inner(options)?))
            }
            ObjectId::ReferenceTypeAttributes_Encoding_DefaultBinary => {
                Ok(Self::ReferenceType(obj.decode_inner(options)?))
            }
            ObjectId::DataTypeAttributes_Encoding_DefaultBinary => {
                Ok(Self::DataType(obj.decode_inner(options)?))
            }
            ObjectId::ViewAttributes_Encoding_DefaultBinary => {
                Ok(Self::View(obj.decode_inner(options)?))
            }
            ObjectId::GenericAttributes_Encoding_DefaultBinary => {
                Ok(Self::Generic(obj.decode_inner(options)?))
            }
            _ => Err(StatusCode::BadNodeAttributesInvalid),
        }
    }

    pub fn as_extension_object(&self) -> ExtensionObject {
        match self {
            AddNodeAttributes::Object(o) => ExtensionObject::from_encodable(
                ObjectId::ObjectAttributes_Encoding_DefaultBinary,
                o,
            ),
            AddNodeAttributes::Variable(o) => ExtensionObject::from_encodable(
                ObjectId::VariableAttributes_Encoding_DefaultBinary,
                o,
            ),
            AddNodeAttributes::Method(o) => ExtensionObject::from_encodable(
                ObjectId::MethodAttributes_Encoding_DefaultBinary,
                o,
            ),
            AddNodeAttributes::ObjectType(o) => ExtensionObject::from_encodable(
                ObjectId::ObjectTypeAttributes_Encoding_DefaultBinary,
                o,
            ),
            AddNodeAttributes::VariableType(o) => ExtensionObject::from_encodable(
                ObjectId::VariableTypeAttributes_Encoding_DefaultBinary,
                o,
            ),
            AddNodeAttributes::ReferenceType(o) => ExtensionObject::from_encodable(
                ObjectId::ReferenceTypeAttributes_Encoding_DefaultBinary,
                o,
            ),
            AddNodeAttributes::DataType(o) => ExtensionObject::from_encodable(
                ObjectId::DataTypeAttributes_Encoding_DefaultBinary,
                o,
            ),
            AddNodeAttributes::View(o) => {
                ExtensionObject::from_encodable(ObjectId::ViewAttributes_Encoding_DefaultBinary, o)
            }
            AddNodeAttributes::Generic(o) => ExtensionObject::from_encodable(
                ObjectId::GenericAttributes_Encoding_DefaultBinary,
                o,
            ),
            AddNodeAttributes::None => todo!(),
        }
    }
}
