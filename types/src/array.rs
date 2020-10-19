use crate::variant::*;

pub(crate) const ARRAY_DIMENSIONS_BIT: u8 = 1 << 6;
pub(crate) const ARRAY_VALUES_BIT: u8 = 1 << 7;

/// An array is a vector of values with an optional number of dimensions.
/// It is expected that the multi-dimensional array is valid, or it might not be encoded or decoded
/// properly. The dimensions should match the number of values, or the array is invalid.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Array {
    /// Values are stored sequentially
    pub values: Vec<Variant>,

    /// Multi dimension array which can contain any scalar type, all the same type. Nested
    /// arrays are rejected. Higher rank dimensions are serialized first. For example an array
    /// with dimensions [2,2,2] is written in this order - [0,0,0], [0,0,1], [0,1,0], [0,1,1],
    /// [1,0,0], [1,0,1], [1,1,0], [1,1,1].
    pub dimensions: Vec<u32>,
}

impl Array {
    pub fn new_single<V>(values: V) -> Array
    where
        V: Into<Vec<Variant>>,
    {
        Array {
            values: values.into(),
            dimensions: Vec::new(),
        }
    }

    pub fn new_multi<V, D>(values: V, dimensions: D) -> Array
    where
        V: Into<Vec<Variant>>,
        D: Into<Vec<u32>>,
    {
        Array {
            values: values.into(),
            dimensions: dimensions.into(),
        }
    }

    pub fn is_valid(&self) -> bool {
        self.is_valid_dimensions() && Self::array_is_valid(&self.values)
    }

    pub fn has_dimensions(&self) -> bool {
        !self.dimensions.is_empty()
    }

    pub fn encoding_mask(&self) -> u8 {
        let mut encoding_mask = if self.values.is_empty() {
            0u8
        } else {
            self.values[0].encoding_mask()
        };
        encoding_mask |= ARRAY_VALUES_BIT;
        if self.has_dimensions() {
            encoding_mask |= ARRAY_DIMENSIONS_BIT;
        }
        encoding_mask
    }

    /// Tests that the variants in the slice all have the same variant type
    fn array_is_valid(values: &[Variant]) -> bool {
        if values.is_empty() {
            true
        } else {
            let expected_type_id = values[0].type_id();
            if expected_type_id == VariantTypeId::Array {
                // Nested arrays are explicitly NOT allowed
                error!("Variant array contains nested array {:?}", expected_type_id);
                false
            } else if values.len() > 1 {
                values_are_of_type(&values[1..], expected_type_id)
            } else {
                // Only contains 1 element
                true
            }
        }
    }

    fn is_valid_dimensions(&self) -> bool {
        // Check that the array dimensions match the length of the array
        let mut length: usize = 1;
        for d in &self.dimensions {
            // Check for invalid dimensions
            if *d == 0 {
                // This dimension has no fixed size, so skip it
                continue;
            }
            length *= *d as usize;
        }
        length <= self.values.len()
    }
}

/// Check that all elements in the slice of arrays are the same type.
pub fn values_are_of_type(values: &[Variant], expected_type: VariantTypeId) -> bool {
    // Ensure all remaining elements are the same type as the first element
    let found_unexpected = values.iter().any(|v| v.type_id() != expected_type);
    if found_unexpected {
        error!(
            "Variant array's type is expected to be {:?} but found other types in it",
            expected_type
        );
    };
    !found_unexpected
}
