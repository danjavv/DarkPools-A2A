use chrono::{DateTime, Utc};
use sl_compute::types::ArithmeticShare;

#[derive(Clone, Debug)]
pub struct OrderShare {
    /// 0/false for buy and 1/true for sell
    pub o_type: bool,

    pub symbol: String,

    pub quantity: ArithmeticShare,

    pub price: ArithmeticShare,

    pub min_execution: ArithmeticShare,

    pub timestamp: DateTime<Utc>,
}
