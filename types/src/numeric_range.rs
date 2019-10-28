//! Contains the implementation of `NumericRange`.

use std::str::FromStr;

use regex::Regex;

use crate::variant::Variant;

/// Numeric range describes a range within an array. See OPCUA Part 4 7.22
///
/// This parameter is defined in Table 159. A formal BNF definition of the numeric range can be
/// found in Clause A.3.
///
/// The syntax for the string contains one of the following two constructs. The first construct is
/// the string representation of an individual integer. For example, `6` is valid, but `6,0` and
/// `3,2` are not. The minimum and maximum values that can be expressed are defined by the use
/// of this parameter and not by this parameter type definition. The second construct is a range
/// represented by two integers separated by the colon (`:`) character. The first integer shall
/// always have a lower value than the second. For example, `5:7` is valid, while `7:5` and `5:5`
/// are not. The minimum and maximum values that can be expressed by these integers are defined by
/// the use of this parameter, and not by this parameter type definition. No other characters,
/// including white-space characters, are permitted.
///
/// Multi-dimensional arrays can be indexed by specifying a range for each dimension separated by
/// a `,`. For example, a 2x2 block in a 4x4 matrix could be selected with the range `1:2,0:1`.
/// A single element in a multi-dimensional array can be selected by specifying a single number
/// instead of a range. For example, `1,1` specifies selects the `[1,1]` element in a two dimensional
/// array.
///
/// Dimensions are specified in the order that they appear in the ArrayDimensions Attribute. All
/// dimensions shall be specified for a NumericRange to be valid.
///
/// All indexes start with `0`. The maximum value for any index is one less than the length of the
/// dimension.
#[derive(Debug, Clone, PartialEq)]
pub enum NumericRange {
    /// A single index
    Index(u32),
    /// A range of indices
    Range(u32, u32),
    /// Multiple ranges contains any mix of Index, Range values - a multiple range containing multiple ranges is invalid
    MultipleRanges(Vec<NumericRange>),
}

// Valid inputs
#[test]
fn valid_numeric_ranges() {
    let valid_ranges = vec![
        ("0", NumericRange::Index(0), "0"),
        ("0000", NumericRange::Index(0), "0"),
        ("1", NumericRange::Index(1), "1"),
        ("0123456789", NumericRange::Index(123456789), "123456789"),
        ("4294967295", NumericRange::Index(4294967295), "4294967295"),
        ("1:2", NumericRange::Range(1, 2), "1:2"),
        ("2:3", NumericRange::Range(2, 3), "2:3"),
        ("0:1,0:2,0:3,0:4,0:5", NumericRange::MultipleRanges(vec![
            NumericRange::Range(0, 1),
            NumericRange::Range(0, 2),
            NumericRange::Range(0, 3),
            NumericRange::Range(0, 4),
            NumericRange::Range(0, 5)
        ]), "0:1,0:2,0:3,0:4,0:5"),
        ("0:1,2,3,0:4,5,6,7,8,0:9", NumericRange::MultipleRanges(vec![
            NumericRange::Range(0, 1),
            NumericRange::Index(2),
            NumericRange::Index(3),
            NumericRange::Range(0, 4),
            NumericRange::Index(5),
            NumericRange::Index(6),
            NumericRange::Index(7),
            NumericRange::Index(8),
            NumericRange::Range(0, 9)
        ]), "0:1,2,3,0:4,5,6,7,8,0:9")
    ];
    for vr in valid_ranges {
        let range = vr.0.parse::<NumericRange>();
        if range.is_err() {
            println!("Range {} is in error when it should be ok", vr.0);
        }
        assert!(range.is_ok());
        assert_eq!(range.unwrap(), vr.1);
        assert_eq!(vr.2, &vr.1.as_string());
    }
}

#[test]
fn invalid_numeric_ranges() {
    // Invalid values are either malformed, min >= max, or they exceed limits on size of numbers
    // or number of indices.
    let invalid_ranges = vec![
        "", " ", " 1", "1 ", ":", ":1", "1:1", "2:1", "1:", "1:1:2", ",", ":,", ",:",
        ",1", "1,", "1,2,", "1,,2", "01234567890", "0,1,2,3,4,5,6,7,8,9,10",
        "4294967296", "0:4294967296", "4294967296:0"
    ];
    for vr in invalid_ranges {
        println!("vr = {}", vr);
        let range = vr.parse::<NumericRange>();
        if range.is_ok() {
            println!("Range {} is ok when it should be in error", vr);
        }
        assert!(range.is_err());
    }
}

const MAX_INDICES: usize = 10;

impl FromStr for NumericRange {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // <numeric-range> ::= <dimension> [',' <dimension>]
        // <dimension> ::= <index> [':' <index>]
        // <index> ::= <digit> [<digit>]
        // <digit> ::= '0' | '1' | '2' | '3' | '4' | '5' | '6' | '7' | '8' | '9'

        // Split the string on the comma
        let parts: Vec<_> = s.split(',').collect();
        match parts.len() {
            1 => Self::parse_range(&parts[0]),
            2..=MAX_INDICES => {
                // Multi dimensions
                let mut ranges = Vec::with_capacity(parts.len());
                for p in &parts {
                    if let Ok(range) = Self::parse_range(&p) {
                        ranges.push(range);
                    } else {
                        return Err(());
                    }
                }
                Ok(NumericRange::MultipleRanges(ranges))
            }
            // 0 parts, or more than MAX_INDICES (really????)
            _ => Err(()),
        }
    }
}

impl NumericRange {
    pub fn new<T>(s: T) -> Result<Self, ()> where T: Into<String> {
        Self::from_str(s.into().as_ref())
    }

    pub fn as_string(&self) -> String {
        match *self {
            NumericRange::Index(idx) => {
                format!("{}", idx)
            }
            NumericRange::Range(min, max) => {
                format!("{}:{}", min, max)
            }
            NumericRange::MultipleRanges(ref ranges) => {
                let ranges: Vec<String> = ranges.iter().map(|r| r.as_string()).collect();
                ranges.join(",")
            }
        }
    }

    fn parse_range(s: &str) -> Result<NumericRange, ()> {
        if s.is_empty() {
            Err(())
        } else {
            // Regex checks for number or number:number
            //
            // BNF doesn't appear to care that number could start with a zero, e.g. 0009 etc.
            //
            // To stop insane values, a number must be 10 digits or less regardless of leading
            // zeroes.
            lazy_static! {
                static ref RE: Regex = Regex::new("^(?P<min>[0-9]{1,10})(:(?P<max>[0-9]{1,10}))?$").unwrap();
            }
            if let Some(captures) = RE.captures(s) {
                let min = captures.name("min");
                let max = captures.name("max");
                if min.is_none() && max.is_none() {
                    Err(())
                } else if min.is_some() && max.is_none() {
                    if let Ok(min) = min.unwrap().as_str().parse::<u32>() {
                        Ok(NumericRange::Index(min))
                    } else {
                        Err(())
                    }
                } else if let Ok(min) = min.unwrap().as_str().parse::<u32>() {
                    if let Ok(max) = max.unwrap().as_str().parse::<u32>() {
                        if min >= max {
                            Err(())
                        } else {
                            Ok(NumericRange::Range(min, max))
                        }
                    } else {
                        Err(())
                    }
                } else {
                    Err(())
                }
            } else {
                Err(())
            }
        }
    }

    /// Tests if the range is basically valid, i.e. that the min < max, that multiple ranges
    /// doesn't point to multiple ranges
    pub fn is_valid(&self) -> bool {
        match *self {
            NumericRange::Index(_) => true,
            NumericRange::Range(min, max) => { min < max }
            NumericRange::MultipleRanges(ref ranges) => {
                let mut valid = true;
                for r in ranges {
                    match *r {
                        NumericRange::MultipleRanges(_) => {
                            // Nested multiple ranges is not allowed
                            valid = false;
                            break;
                        }
                        _ => {
                            if !r.is_valid() {
                                valid = false;
                                break;
                            }
                        }
                    }
                }
                valid
            }
        }
    }

    // This version should test the range against the supplied array
    pub fn is_valid_for_array(&self, array: &Variant) -> bool {
        match *array {
            Variant::Array(_) => {
                // Only accept range / index numeric ranges. Members of range have to be inside array
                unimplemented!();
            }
            Variant::MultiDimensionArray(_) => {
                // Only accept multi dimension numeric range with same # of dimensions as the array
                // ensure that each range / index is inside that array dimension
                unimplemented!();
            }
            _ => {
                panic!("The array is not an array")
            }
        }
    }
}
