use pensionmint_core::db::DatabaseTransaction;
use pensionmint_core::encoding::{Decodable, Encodable};
use pensionmint_core::epoch::{SerdeSignature, SerdeSignatureShare};
use pensionmint_core::{impl_db_lookup, impl_db_record, Amount, OutPoint, PeerId};
use futures::StreamExt;
use secp256k1::XOnlyPublicKey;
use serde::Serialize;
use strum_macros::EnumIter;

use crate::OutputOutcome;

/// Namespaces DB keys for this module
#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    Funds = 0x01,
    Outcome = 0x02,
    SignatureShare = 0x03,
    Signature = 0x04,
}

// TODO: Boilerplate-code
impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Example old version 0 of DB entries
// TODO: can we simplify this by just using macros?
#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize)]
pub struct FundsKeyV0(pub XOnlyPublicKey);

#[derive(Debug, Encodable, Decodable)]
pub struct FundsKeyPrefixV0;

impl_db_record!(
    key = FundsKeyV0,
    value = (),
    db_prefix = DbKeyPrefix::Funds,
);
impl_db_lookup!(key = FundsKeyV0, query_prefix = FundsKeyPrefixV0);

/// Lookup funds for a user by key or prefix
#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize)]
pub struct FundsKeyV1(pub XOnlyPublicKey);

#[derive(Debug, Encodable, Decodable)]
pub struct FundsPrefixV1;

impl_db_record!(
    key = FundsKeyV1,
    value = Amount,
    db_prefix = DbKeyPrefix::Funds,
);
impl_db_lookup!(key = FundsKeyV1, query_prefix = FundsPrefixV1);

/// Example DB migration from version 0 to version 1
pub async fn migrate_to_v1(dbtx: &mut DatabaseTransaction<'_>) -> Result<(), anyhow::Error> {
    // Select old entries
    let v0_entries = dbtx
        .find_by_prefix(&FundsKeyPrefixV0)
        .await
        .collect::<Vec<(FundsKeyV0, ())>>()
        .await;

    // Remove old entries
    dbtx.remove_by_prefix(&FundsKeyPrefixV0).await;

    // Migrate to new entries
    for (v0_key, _v0_val) in v0_entries {
        let v1_key = FundsKeyV1(v0_key.0);
        dbtx.insert_new_entry(&v1_key, &Amount::ZERO).await;
    }
    Ok(())
}

/// Lookup tx outputs by key or prefix
#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize)]
pub struct OutcomeKey(pub OutPoint);

#[derive(Debug, Encodable, Decodable)]
pub struct OutcomePrefix;

impl_db_record!(
    key = OutcomeKey,
    value = OutputOutcome,
    db_prefix = DbKeyPrefix::Outcome,
);
impl_db_lookup!(key = OutcomeKey, query_prefix = OutcomePrefix);

/// Lookup signature requests by key or prefix
#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize)]
pub struct SignatureShareKey(pub String, pub PeerId);

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize)]
pub struct SignatureShareStringPrefix(pub String);

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize)]
pub struct SignatureSharePrefix;

impl_db_record!(
    key = SignatureShareKey,
    value = SerdeSignatureShare,
    db_prefix = DbKeyPrefix::SignatureShare,
);
impl_db_lookup!(
    key = SignatureShareKey,
    query_prefix = SignatureShareStringPrefix,
    query_prefix = SignatureSharePrefix
);

/// Lookup signature requests by key or prefix
#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize)]
pub struct SignatureKey(pub String);

#[derive(Debug, Encodable, Decodable)]
pub struct SignaturePrefix;

impl_db_record!(
    key = SignatureKey,
    value = Option<SerdeSignature>,
    db_prefix = DbKeyPrefix::Signature,
    // Allows us to listen for notifications on this key
    notify_on_modify = true
);
impl_db_lookup!(key = SignatureKey, query_prefix = SignaturePrefix);