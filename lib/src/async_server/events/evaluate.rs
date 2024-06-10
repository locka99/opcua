use std::cmp::Ordering;

use regex::Regex;

use crate::server::prelude::{
    EventFieldList, FilterOperator, NumericRange, Operand, SimpleAttributeOperand, Variant,
    VariantTypeId,
};

use super::{
    event::Event,
    validation::{ParsedContentFilter, ParsedEventFilter},
};

impl ParsedEventFilter {
    pub fn evaluate(&self, event: &dyn Event, client_handle: u32) -> Option<EventFieldList> {
        if !self.content_filter.evaluate(event) {
            return None;
        }

        let fields: Vec<_> = self
            .select_clauses
            .iter()
            .map(|c| get_field(event, c))
            .collect();
        Some(EventFieldList {
            client_handle,
            event_fields: Some(fields),
        })
    }
}

macro_rules! cmp_op {
    ($slf:ident, $evt:ident, $op:ident, $pt:pat) => {
        matches!(
            ParsedContentFilter::compare_op(
                $slf.evaluate_operand($evt, &$op.operands[0]),
                $slf.evaluate_operand($evt, &$op.operands[1]),
            ),
            $pt
        )
        .into()
    };
}

macro_rules! as_type {
    ($v:expr, $t:ident, $def:expr) => {{
        let v = $v.convert(VariantTypeId::$t);
        let Variant::$t(v) = v else {
            return $def;
        };
        v
    }};
}

macro_rules! bw_op {
    ($lhs:expr, $rhs:expr, $op:expr) => {{
        match $op {
            BitOperation::And => ($lhs & $rhs).into(),
            BitOperation::Or => ($lhs | $rhs).into(),
        }
    }};
}

enum BitOperation {
    And,
    Or,
}

impl ParsedContentFilter {
    pub fn evaluate(&self, event: &dyn Event) -> bool {
        if self.elements.is_empty() {
            return true;
        }
        matches!(self.evulate_element(event, 0), Variant::Boolean(true))
    }

    fn evulate_element(&self, event: &dyn Event, index: usize) -> Variant {
        let Some(op) = self.elements.get(index) else {
            return Variant::Empty;
        };

        match op.operator {
            FilterOperator::Equals => cmp_op!(self, event, op, Some(Ordering::Equal)),
            FilterOperator::IsNull => {
                (self.evaluate_operand(event, &op.operands[0]) == Variant::Empty).into()
            }
            FilterOperator::GreaterThan => cmp_op!(self, event, op, Some(Ordering::Greater)),
            FilterOperator::LessThan => cmp_op!(self, event, op, Some(Ordering::Less)),
            FilterOperator::GreaterThanOrEqual => {
                cmp_op!(self, event, op, Some(Ordering::Equal | Ordering::Greater))
            }
            FilterOperator::LessThanOrEqual => {
                cmp_op!(self, event, op, Some(Ordering::Equal | Ordering::Less))
            }
            FilterOperator::Like => Self::like(
                self.evaluate_operand(event, &op.operands[0]),
                self.evaluate_operand(event, &op.operands[1]),
            )
            .into(),
            FilterOperator::Not => Self::not(self.evaluate_operand(event, &op.operands[0])),
            FilterOperator::Between => Self::between(
                self.evaluate_operand(event, &op.operands[0]),
                self.evaluate_operand(event, &op.operands[1]),
                self.evaluate_operand(event, &op.operands[2]),
            )
            .into(),
            FilterOperator::InList => Self::in_list(
                self.evaluate_operand(event, &op.operands[0]),
                op.operands
                    .iter()
                    .skip(1)
                    .map(|o| self.evaluate_operand(event, o)),
            )
            .into(),
            FilterOperator::And => Self::and(
                self.evaluate_operand(event, &op.operands[0]),
                self.evaluate_operand(event, &op.operands[1]),
            ),
            FilterOperator::Or => Self::or(
                self.evaluate_operand(event, &op.operands[0]),
                self.evaluate_operand(event, &op.operands[1]),
            ),
            FilterOperator::Cast => Self::cast(
                self.evaluate_operand(event, &op.operands[0]),
                self.evaluate_operand(event, &op.operands[1]),
            ),
            FilterOperator::BitwiseAnd => Self::bitwise_op(
                self.evaluate_operand(event, &op.operands[0]),
                self.evaluate_operand(event, &op.operands[1]),
                BitOperation::And,
            ),
            FilterOperator::BitwiseOr => Self::bitwise_op(
                self.evaluate_operand(event, &op.operands[0]),
                self.evaluate_operand(event, &op.operands[1]),
                BitOperation::Or,
            ),
            _ => Variant::Empty,
        }
    }

    fn evaluate_operand(&self, event: &dyn Event, op: &Operand) -> Variant {
        match op {
            Operand::ElementOperand(o) => self.evulate_element(event, o.index as usize),
            Operand::LiteralOperand(o) => o.value.clone(),
            Operand::AttributeOperand(_) => unreachable!(),
            Operand::SimpleAttributeOperand(o) => get_field(event, o),
        }
    }

    fn in_list(lhs: Variant, rhs: impl Iterator<Item = Variant>) -> bool {
        for it in rhs {
            if matches!(Self::compare_op(lhs.clone(), it), Some(Ordering::Equal)) {
                return true;
            }
        }
        false
    }

    fn between(it: Variant, gte: Variant, lte: Variant) -> bool {
        matches!(
            Self::compare_op(it.clone(), gte),
            Some(Ordering::Greater | Ordering::Equal)
        ) && matches!(
            Self::compare_op(it, lte),
            Some(Ordering::Less | Ordering::Equal)
        )
    }

    fn not(rhs: Variant) -> Variant {
        let rhs = as_type!(rhs, Boolean, Variant::Empty);
        (!rhs).into()
    }

    fn and(lhs: Variant, rhs: Variant) -> Variant {
        let lhs = as_type!(lhs, Boolean, Variant::Empty);
        let rhs = as_type!(rhs, Boolean, Variant::Empty);

        (lhs && rhs).into()
    }

    fn or(lhs: Variant, rhs: Variant) -> Variant {
        let lhs = as_type!(lhs, Boolean, Variant::Empty);
        let rhs = as_type!(rhs, Boolean, Variant::Empty);

        (lhs || rhs).into()
    }

    fn like(lhs: Variant, rhs: Variant) -> bool {
        let lhs = as_type!(lhs, String, false);
        let rhs = as_type!(rhs, String, false);
        let Ok(re) = like_to_regex(rhs.as_ref()) else {
            return false;
        };
        re.is_match(lhs.as_ref())
    }

    fn cast(lhs: Variant, rhs: Variant) -> Variant {
        let type_id = match rhs {
            Variant::NodeId(n) => {
                let Ok(t) = VariantTypeId::try_from(&*n) else {
                    return Variant::Empty;
                };
                t
            }
            Variant::ExpandedNodeId(n) => {
                let Ok(t) = VariantTypeId::try_from(&n.node_id) else {
                    return Variant::Empty;
                };
                t
            }
            _ => return Variant::Empty,
        };
        lhs.cast(type_id)
    }

    fn convert(lhs: Variant, rhs: Variant) -> (Variant, Variant) {
        let lhs_type = lhs.type_id();
        match lhs_type.precedence().cmp(&rhs.type_id().precedence()) {
            std::cmp::Ordering::Less => (lhs, rhs.convert(lhs_type)),
            std::cmp::Ordering::Equal => (lhs, rhs),
            std::cmp::Ordering::Greater => (lhs.convert(rhs.type_id()), rhs),
        }
    }

    fn bitwise_op(lhs: Variant, rhs: Variant, op: BitOperation) -> Variant {
        let (lhs, rhs) = Self::convert(lhs, rhs);

        match (lhs, rhs) {
            (Variant::SByte(lhs), Variant::SByte(rhs)) => bw_op!(lhs, rhs, op),
            (Variant::Byte(lhs), Variant::Byte(rhs)) => bw_op!(lhs, rhs, op),
            (Variant::Int16(lhs), Variant::Int16(rhs)) => bw_op!(lhs, rhs, op),
            (Variant::Int32(lhs), Variant::Int32(rhs)) => bw_op!(lhs, rhs, op),
            (Variant::Int64(lhs), Variant::Int64(rhs)) => bw_op!(lhs, rhs, op),
            (Variant::UInt16(lhs), Variant::UInt16(rhs)) => bw_op!(lhs, rhs, op),
            (Variant::UInt32(lhs), Variant::UInt32(rhs)) => bw_op!(lhs, rhs, op),
            (Variant::UInt64(lhs), Variant::UInt64(rhs)) => bw_op!(lhs, rhs, op),
            _ => Variant::Empty,
        }
    }

    fn compare_op(lhs: Variant, rhs: Variant) -> Option<Ordering> {
        let (lhs, rhs) = Self::convert(lhs, rhs);
        match (lhs, rhs) {
            (Variant::SByte(lhs), Variant::SByte(rhs)) => Some(lhs.cmp(&rhs)),
            (Variant::Byte(lhs), Variant::Byte(rhs)) => Some(lhs.cmp(&rhs)),
            (Variant::Int16(lhs), Variant::Int16(rhs)) => Some(lhs.cmp(&rhs)),
            (Variant::Int32(lhs), Variant::Int32(rhs)) => Some(lhs.cmp(&rhs)),
            (Variant::Int64(lhs), Variant::Int64(rhs)) => Some(lhs.cmp(&rhs)),
            (Variant::UInt16(lhs), Variant::UInt16(rhs)) => Some(lhs.cmp(&rhs)),
            (Variant::UInt32(lhs), Variant::UInt32(rhs)) => Some(lhs.cmp(&rhs)),
            (Variant::UInt64(lhs), Variant::UInt64(rhs)) => Some(lhs.cmp(&rhs)),
            (Variant::Double(lhs), Variant::Double(rhs)) => Some(lhs.total_cmp(&rhs)),
            (Variant::Float(lhs), Variant::Float(rhs)) => Some(lhs.total_cmp(&rhs)),
            (Variant::Boolean(lhs), Variant::Boolean(rhs)) => Some(lhs.cmp(&rhs)),
            _ => None,
        }
    }
}

fn get_field(event: &dyn Event, attr: &SimpleAttributeOperand) -> Variant {
    let index_range = attr
        .index_range
        .as_ref()
        .parse::<NumericRange>()
        .unwrap_or(NumericRange::None);
    let Some(path) = &attr.browse_path else {
        return Variant::Empty;
    };

    event.get_field(
        &attr.type_definition_id,
        &path,
        attr.attribute_id,
        index_range,
    )
}

/// Converts the OPC UA SQL-esque Like format into a regular expression.
fn like_to_regex(v: &str) -> Result<Regex, ()> {
    // Give a reasonable buffer
    let mut pattern = String::with_capacity(v.len() * 2);

    let mut in_list = false;

    // Turn the chars into a vec to make it easier to index them
    let v = v.chars().collect::<Vec<char>>();

    pattern.push('^');
    v.iter().enumerate().for_each(|(i, c)| {
        if in_list {
            if *c == ']' && (i == 0 || v[i - 1] != '\\') {
                // Close the list
                in_list = false;
                pattern.push(*c);
            } else {
                // Chars in list are escaped if required
                match c {
                    '$' | '(' | ')' | '.' | '+' | '*' | '?' => {
                        // Other regex chars except for ^ are escaped
                        pattern.push('\\');
                        pattern.push(*c);
                    }
                    _ => {
                        // Everything between two [] will be treated as-is
                        pattern.push(*c);
                    }
                }
            }
        } else {
            match c {
                '$' | '^' | '(' | ')' | '.' | '+' | '*' | '?' => {
                    // Other regex chars are escaped
                    pattern.push('\\');
                    pattern.push(*c);
                }
                '[' => {
                    // Opens a list of chars to match
                    if i == 0 || v[i - 1] != '\\' {
                        // Open the list
                        in_list = true;
                    }
                    pattern.push(*c);
                }
                '%' => {
                    if i == 0 || v[i - 1] != '\\' {
                        // A % is a match on zero or more chans unless it is escaped
                        pattern.push_str(".*");
                    } else {
                        pattern.push(*c);
                    }
                }
                '_' => {
                    if i == 0 || v[i - 1] != '\\' {
                        // A _ is a match on a single char unless it is escaped
                        pattern.push('?');
                    } else {
                        // Remove escaping of the underscore
                        let _ = pattern.pop();
                        pattern.push(*c);
                    }
                }
                _ => {
                    pattern.push(*c);
                }
            }
        }
    });
    pattern.push('$');
    Regex::new(&pattern).map_err(|err| {
        error!("Problem parsing, error = {}", err);
    })
}

#[cfg(test)]
mod tests {
    use regex::Regex;

    use crate::async_server::events::evaluate::like_to_regex;

    fn compare_regex(r1: Regex, r2: Regex) {
        assert_eq!(r1.as_str(), r2.as_str());
    }

    #[test]
    fn like_to_regex_tests() {
        compare_regex(like_to_regex("").unwrap(), Regex::new("^$").unwrap());
        compare_regex(like_to_regex("^$").unwrap(), Regex::new(r"^\^\$$").unwrap());
        compare_regex(like_to_regex("%").unwrap(), Regex::new("^.*$").unwrap());
        compare_regex(like_to_regex("[%]").unwrap(), Regex::new("^[%]$").unwrap());
        compare_regex(like_to_regex("[_]").unwrap(), Regex::new("^[_]$").unwrap());
        compare_regex(
            like_to_regex(r"[\]]").unwrap(),
            Regex::new(r"^[\]]$").unwrap(),
        );
        compare_regex(
            like_to_regex("[$().+*?]").unwrap(),
            Regex::new(r"^[\$\(\)\.\+\*\?]$").unwrap(),
        );
        compare_regex(like_to_regex("_").unwrap(), Regex::new("^?$").unwrap());
        compare_regex(
            like_to_regex("[a-z]").unwrap(),
            Regex::new("^[a-z]$").unwrap(),
        );
        compare_regex(
            like_to_regex("[abc]").unwrap(),
            Regex::new("^[abc]$").unwrap(),
        );
        compare_regex(
            like_to_regex(r"\[\]").unwrap(),
            Regex::new(r"^\[\]$").unwrap(),
        );
        compare_regex(
            like_to_regex("[^0-9]").unwrap(),
            Regex::new("^[^0-9]$").unwrap(),
        );

        // Some samples from OPC UA part 4
        let re = like_to_regex("Th[ia][ts]%").unwrap();
        assert!(re.is_match("That is fine"));
        assert!(re.is_match("This is fine"));
        assert!(re.is_match("That as one"));
        assert!(!re.is_match("Then at any")); // Spec says this should pass when it obviously wouldn't

        let re = like_to_regex("%en%").unwrap();
        assert!(re.is_match("entail"));
        assert!(re.is_match("green"));
        assert!(re.is_match("content"));

        let re = like_to_regex("abc[13-68]").unwrap();
        assert!(re.is_match("abc1"));
        assert!(!re.is_match("abc2"));
        assert!(re.is_match("abc3"));
        assert!(re.is_match("abc4"));
        assert!(re.is_match("abc5"));
        assert!(re.is_match("abc6"));
        assert!(!re.is_match("abc7"));
        assert!(re.is_match("abc8"));

        let re = like_to_regex("ABC[^13-5]").unwrap();
        assert!(!re.is_match("ABC1"));
        assert!(re.is_match("ABC2"));
        assert!(!re.is_match("ABC3"));
        assert!(!re.is_match("ABC4"));
        assert!(!re.is_match("ABC5"));
    }
}
