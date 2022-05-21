use crate::types::variant::*;
use crate::types::StatusCode;

/// An array is a vector of values with an optional number of dimensions.
/// It is expected that the multi-dimensional array is valid, or it might not be encoded or decoded
/// properly. The dimensions should match the number of values, or the array is invalid.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Array {
    // Type of elements in the array
    pub value_type: VariantTypeId,

    /// Values are stored sequentially
    pub values: Vec<Variant>,

    /// Multi dimension array which can contain any scalar type, all the same type. Nested
    /// arrays are rejected. Higher rank dimensions are serialized first. For example an array
    /// with dimensions [2,2,2] is written in this order - [0,0,0], [0,0,1], [0,1,0], [0,1,1],
    /// [1,0,0], [1,0,1], [1,1,0], [1,1,1].
    pub dimensions: Vec<u32>,
}

impl Array {
    pub fn new_single<V>(value_type: VariantTypeId, values: V) -> Result<Array, StatusCode>
    where
        V: Into<Vec<Variant>>,
    {
        let values = values.into();
        if Self::validate_array_type_to_values(value_type, &values) {
            Ok(Array {
                value_type,
                values,
                dimensions: Vec::new(),
            })
        } else {
            Err(StatusCode::BadDecodingError)
        }
    }

    pub fn new_multi<V, D>(
        value_type: VariantTypeId,
        values: V,
        dimensions: D,
    ) -> Result<Array, StatusCode>
    where
        V: Into<Vec<Variant>>,
        D: Into<Vec<u32>>,
    {
        let values = values.into();
        if Self::validate_array_type_to_values(value_type, &values) {
            Ok(Array {
                value_type,
                values,
                dimensions: dimensions.into(),
            })
        } else {
            Err(StatusCode::BadDecodingError)
        }
    }

    /// This is a runtime check to ensure the type of the array also matches the types of the variants in the array.
    fn validate_array_type_to_values(value_type: VariantTypeId, values: &[Variant]) -> bool {
        match value_type {
            VariantTypeId::Array | VariantTypeId::Empty => {
                error!("Invalid array type supplied");
                false
            }
            _ => {
                if !values_are_of_type(values, value_type) {
                    // If the values exist, then validate them to the type
                    error!("Value type of array does not match contents");
                    false
                } else {
                    true
                }
            }
        }
    }

    pub fn is_valid(&self) -> bool {
        self.is_valid_dimensions() && Self::array_is_valid(&self.values)
    }

    pub fn has_dimensions(&self) -> bool {
        !self.dimensions.is_empty()
    }

    pub fn encoding_mask(&self) -> u8 {
        let mut encoding_mask = self.value_type.encoding_mask();
        encoding_mask |= EncodingMask::ARRAY_VALUES_BIT;
        if self.has_dimensions() {
            encoding_mask |= EncodingMask::ARRAY_DIMENSIONS_BIT;
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
