use kmip::types::{
    request::BatchItem,
    response::{BatchItem as ResBatchItem, ResultReason},
};

use crate::config::Cfg;
use crate::kmip::util::mk_err_batch_item;

pub fn op(
    _cfg: &Cfg,
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
