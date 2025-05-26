use crate::types::FieldElement;
use crate::{
    constants::FRACTION_LENGTH,
    types::{ArithmeticShare, DecimalShare},
};

/// Converts DecimalShare (money amount in cents) to ArithmeticShare (fixed point share)
pub fn decimal_to_arithmetic(share: &DecimalShare) -> ArithmeticShare {
    share
        .to_arithmetic()
        .mul_const(&FieldElement::from(1u64 << FRACTION_LENGTH))
}
