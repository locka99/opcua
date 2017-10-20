use std::str::FromStr;

use regex::Regex;

use basic_types::UInt32;

/// See OPCUA Part 4 7.22
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
pub enum NumericRange {
    Index(UInt32),
    Range(UInt32, UInt32),
    // Multi dimensional range
}

// Valid inputs
//#[test]
fn valid_numeric_ranges() {
    let valid_ranges = vec!["0", "1", "1:2", "2:3", "0:100"];
    for vr in valid_ranges {
        let range = NumericRange::from_str(vr);
        assert!(range.is_ok());
    }
}

//#[test]
fn invalid_numeric_ranges() {
    let valid_ranges = vec!["", ":", ":1", "1:", "1:1:2", ",", ":,", ",:", "1,2,", "1,,2"];
    for vr in valid_ranges {
        println!("vr = {}", vr);
        let range = NumericRange::from_str(vr);
        assert!(range.is_err());
    }
}

impl FromStr for NumericRange {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // <numeric-range> ::= <dimension> [',' <dimension>]
        // <dimension> ::= <index> [':' <index>]
        // <index> ::= <digit> [<digit>]
        // <digit> ::= '0' | '1' | '2' | '3' | '4' | '5' | '6' | '7' | '8' | '9'

        // Split the string into slices
        let parts: Vec<_> = s.split(',').collect();
        if parts.is_empty() {
            Err(())
        } else if parts.len() > 1 {
            // todo multi dimensions
            Err(())
        } else {
            let part = &parts[0];

            if part.is_empty() {
                Err(())
            } else {
                // Regex checks for number or number:number
                lazy_static! {
                    static ref RE: Regex = Regex::new("^((?P<min>[1-9][0-9]*)(:(?P<max>[1-9][0-9]*)))?$").unwrap();
                }
                let captures = RE.captures(s);
                if captures.is_none() {
                    Err(())
                } else {
                    let captures = captures.unwrap();
                    let min = captures.name("min");
                    let max = captures.name("max");
                    if min.is_none() && max.is_none() {
                        Err(())
                    } else if min.is_some() && max.is_none() {
                        let min = min.unwrap().as_str().parse::<UInt32>().unwrap();
                        Ok(NumericRange::Index(min))
                    } else {
                        let min = min.unwrap().as_str().parse::<UInt32>().unwrap();
                        let max = max.unwrap().as_str().parse::<UInt32>().unwrap();
                        Ok(NumericRange::Range(min, max))
                    }
                }
            }
        }
    }
}

impl NumericRange {
    pub fn is_valid(&self) -> bool {
        match *self {
            NumericRange::Index(_) => true,
            NumericRange::Range(min, max) => { min < max }
        }
    }

    // This version should test the range against the supplied array
    // pub fn is_valid_for_array(&self, array: &Variant) -> bool {
}
