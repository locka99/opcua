use crate::server::prelude::{
    AttributeId, ByteString, DateTime, ExtensionObject, LocalizedText, NodeId, NumericRange,
    ObjectId, ObjectTypeId, QualifiedName, TimeZoneDataType, UAString, Variant,
};

pub trait Event {
    fn get_field(
        &self,
        type_definition_id: &NodeId,
        browse_path: &[QualifiedName],
        attribute_id: AttributeId,
        index_range: NumericRange,
    ) -> Variant;

    fn time(&self) -> &DateTime;
}

#[derive(Debug, Default)]
/// This corresponds to BaseEventType definition in OPC UA Part 5
pub struct BaseEventType {
    /// A unique identifier for an event, e.g. a GUID in a byte string
    pub event_id: ByteString,
    /// Event type describes the type of event
    pub event_type: NodeId,
    /// Source node identifies the node that the event originated from or null.
    pub source_node: NodeId,
    /// Source name provides the description of the source of the event,
    /// e.g. the display of the event source
    pub source_name: UAString,
    /// Time provides the time the event occurred. As close
    /// to the event generator as possible.
    pub time: DateTime,
    /// Receive time provides the time the OPC UA server received
    /// the event from the underlying device of another server.
    pub receive_time: DateTime,
    /// Local time (optional) is a structure containing
    /// the offset and daylightsaving flag.
    pub local_time: Option<TimeZoneDataType>,
    /// Message provides a human readable localizable text description
    /// of the event.
    pub message: LocalizedText,
    /// Severity is an indication of the urgency of the event. Values from 1 to 1000, with 1 as the lowest
    /// severity and 1000 being the highest. A value of 1000 would indicate an event of catastrophic nature.
    ///
    /// Guidance:
    ///
    /// * 801-1000 - High
    /// * 601-800 - Medium High
    /// * 401-600 - Medium
    /// * 201-400 - Medium Low
    /// * 1-200 - Low
    pub severity: u16,
    /// Condition Class Id specifies in which domain this Event is used.
    pub condition_class_id: Option<NodeId>,
    /// Condition class name specifies the name of the condition class of this event, if set.
    pub condition_class_name: Option<LocalizedText>,
    /// ConditionSubClassId specifies additional class[es] that apply to the Event.
    /// It is the NodeId of the corresponding subtype of BaseConditionClassType.
    pub condition_sub_class_id: Option<Vec<NodeId>>,
    /// Condition sub class name specifies the names of additional classes that apply to the event.
    pub condition_sub_class_name: Option<Vec<LocalizedText>>,
}

macro_rules! take_value {
    ($v:expr, $r:ident) => {{
        let variant: Variant = $v.clone().into();
        variant.range_of_owned($r).unwrap_or(Variant::Empty)
    }};
}

impl Event for BaseEventType {
    fn get_field(
        &self,
        type_definition_id: &NodeId,
        browse_path: &[QualifiedName],
        attribute_id: AttributeId,
        index_range: NumericRange,
    ) -> Variant {
        let own_type_id: NodeId = ObjectTypeId::BaseEventType.into();
        if type_definition_id != &own_type_id
            || browse_path.len() != 1
            || attribute_id != AttributeId::Value
        {
            // Field is not from base event type.
            return Variant::Empty;
        }
        let field = &browse_path[0];
        if field.namespace_index != 0 {
            return Variant::Empty;
        }

        match field.name.as_ref() {
            "EventId" => take_value!(self.event_id, index_range),
            "EventType" => take_value!(self.event_type, index_range),
            "SourceNode" => take_value!(self.source_node, index_range),
            "SourceName" => take_value!(self.source_name, index_range),
            "Time" => take_value!(self.time, index_range),
            "ReceiveTime" => take_value!(self.receive_time, index_range),
            "LocalTime" => take_value!(
                self.local_time
                    .as_ref()
                    .map(|t| ExtensionObject::from_encodable(
                        ObjectId::TimeZoneDataType_Encoding_DefaultBinary,
                        t
                    )),
                index_range
            ),
            "Message" => take_value!(self.message, index_range),
            "Severity" => take_value!(self.severity, index_range),
            "ConditionClassId" => take_value!(self.condition_class_id, index_range),
            "ConditionClassName" => take_value!(self.condition_class_name, index_range),
            "ConditionSubClassId" => take_value!(self.condition_sub_class_id, index_range),
            "ConditionSubClassName" => take_value!(self.condition_sub_class_name, index_range),
            _ => Variant::Empty,
        }
    }

    fn time(&self) -> &DateTime {
        &self.time
    }
}

impl BaseEventType {
    pub fn new_now(
        type_id: impl Into<NodeId>,
        event_id: ByteString,
        message: impl Into<LocalizedText>,
    ) -> Self {
        let time = DateTime::now();
        Self::new(type_id, event_id, message, time)
    }

    pub fn new(
        type_id: impl Into<NodeId>,
        event_id: ByteString,
        message: impl Into<LocalizedText>,
        time: DateTime,
    ) -> Self {
        Self {
            event_id,
            event_type: type_id.into(),
            message: message.into(),
            time,
            receive_time: time,
            ..Default::default()
        }
    }
}
