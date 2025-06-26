use kmip::types::{
    request::BatchItem,
    response::{BatchItem as ResBatchItem, ResultReason},
};

use crate::kmip::util::mk_err_batch_item;

pub fn op(
    batch_item: &BatchItem,
) -> std::result::Result<ResBatchItem, (ResultReason, String)> {
    Ok(mk_err_batch_item(
        ResultReason::OperationNotSupported,
        format!(
            "KMIP operation '{}' is not supported",
            batch_item.operation()
        ),
    ))
}
