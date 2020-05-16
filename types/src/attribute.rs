// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2020 Adam Lock

// Attributes as defined in Part 4, Figure B.7

// Attributes sometimes required and sometimes optional

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq)]
pub enum AttributeId {
    NodeId = 1,
    NodeClass = 2,
    BrowseName = 3,
    DisplayName = 4,
    Description = 5,
    WriteMask = 6,
    UserWriteMask = 7,
    IsAbstract = 8,
    Symmetric = 9,
    InverseName = 10,
    ContainsNoLoops = 11,
    EventNotifier = 12,
    Value = 13,
    DataType = 14,
    ValueRank = 15,
    ArrayDimensions = 16,
    AccessLevel = 17,
    UserAccessLevel = 18,
    MinimumSamplingInterval = 19,
    Historizing = 20,
    Executable = 21,
    UserExecutable = 22,
    DataTypeDefinition = 23,
    RolePermissions = 24,
    UserRolePermissions = 25,
    AccessRestrictions = 26,
    AccessLevelEx = 27,
}

impl AttributeId {
    pub fn from_u32(attribute_id: u32) -> Result<AttributeId, ()> {
        let attribute_id = match attribute_id {
            1 => AttributeId::NodeId,
            2 => AttributeId::NodeClass,
            3 => AttributeId::BrowseName,
            4 => AttributeId::DisplayName,
            5 => AttributeId::Description,
            6 => AttributeId::WriteMask,
            7 => AttributeId::UserWriteMask,
            8 => AttributeId::IsAbstract,
            9 => AttributeId::Symmetric,
            10 => AttributeId::InverseName,
            11 => AttributeId::ContainsNoLoops,
            12 => AttributeId::EventNotifier,
            13 => AttributeId::Value,
            14 => AttributeId::DataType,
            15 => AttributeId::ValueRank,
            16 => AttributeId::ArrayDimensions,
            17 => AttributeId::AccessLevel,
            18 => AttributeId::UserAccessLevel,
            19 => AttributeId::MinimumSamplingInterval,
            20 => AttributeId::Historizing,
            21 => AttributeId::Executable,
            22 => AttributeId::UserExecutable,
            23 => AttributeId::DataTypeDefinition,
            24 => AttributeId::RolePermissions,
            25 => AttributeId::UserRolePermissions,
            26 => AttributeId::AccessRestrictions,
            27 => AttributeId::AccessLevelEx,
            _ => {
                debug!("Invalid attribute id {}", attribute_id);
                return Err(());
            }
        };
        Ok(attribute_id)
    }
}
