//! Boot-time pinning of the Master key identity.
//!
//! Every authorization decision branches on `api_key::Model::is_master`, read straight out of a
//! database column. `RBAC_MODEL.md` §5's uniqueness constraint stops a second Master from being
//! *written*, but it does not stop the *running process* from trusting a column value that changed
//! underneath it via direct database access. So the Master identity is resolved once at boot, held
//! in memory for the process lifetime, and any other row later claiming `is_master = true` is
//! demoted in place rather than trusted.

use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use tokio::sync::OnceCell;
use uuid::Uuid;

use crate::entities::{api_key, prelude::ApiKey};

/// The unique index `RBAC_MODEL.md` §5 requires over the engine-derived master marker.
const MASTER_MARKER_INDEX: &str = "idx_api_keys_master_marker";
/// The table the index above belongs to.
const API_KEYS_TABLE: &str = "api_keys";

/// Why the Master identity could not be established at boot.
#[derive(Debug)]
pub enum MasterPinError {
    /// No key carries `is_master`.
    NoMaster,
    /// More than one key carries `is_master`.
    Duplicates(Vec<Uuid>),
    /// The §5 uniqueness index is missing from the schema.
    MissingConstraint,
    /// The database could not be queried at all.
    Db(sea_orm::DbErr),
}

impl std::fmt::Display for MasterPinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoMaster => write!(
                f,
                "no key has is_master = true; restart the service and the bootstrap path will \
                 re-mint it."
            ),
            Self::Duplicates(ids) => write!(
                f,
                "{} keys have is_master = true ({}), but RBAC_MODEL.md §5 requires exactly one. \
                 Decide which key is the Master and demote the others with `UPDATE api_keys SET \
                 is_master = false WHERE id IN (...);`, then restart.",
                ids.len(),
                ids.iter().map(Uuid::to_string).collect::<Vec<_>>().join(", ")
            ),
            Self::MissingConstraint => write!(
                f,
                "the unique index '{MASTER_MARKER_INDEX}' is missing from '{API_KEYS_TABLE}'. \
                 Re-run migrations."
            ),
            Self::Db(e) => write!(f, "could not query the database to establish the master key: {e}"),
        }
    }
}

impl std::error::Error for MasterPinError {}

impl From<sea_orm::DbErr> for MasterPinError {
    fn from(e: sea_orm::DbErr) -> Self {
        Self::Db(e)
    }
}

/// The pinned Master key id, resolved once per process.
#[derive(Debug, Default)]
pub struct MasterPin {
    cell: OnceCell<Uuid>,
}

impl MasterPin {
    /// An unresolved pin.
    pub fn new() -> Self {
        Self { cell: OnceCell::new() }
    }

    /// A pin fixed to a known id, without consulting the database. Test-facing.
    pub fn pinned_to(id: Uuid) -> Self {
        let cell = OnceCell::new();
        // A freshly constructed `OnceCell` is always empty, so `set` cannot fail here.
        let _ = cell.set(id);
        Self { cell }
    }

    /// The pinned id, if one has been established.
    pub fn get(&self) -> Option<Uuid> {
        self.cell.get().copied()
    }

    /// Establishes the Master identity at startup, asserting every §5 invariant on the way.
    pub async fn pin_at_boot(&self, db: &DatabaseConnection) -> Result<Uuid, MasterPinError> {
        // `crate::db::has_index` rather than `sea_orm_migration::SchemaManager::has_index`: the
        // latter's catalog query is gated behind cargo features this crate does not enable for
        // PostgreSQL and answers `BackendNotSupported` there — see that function's doc comment.
        if !crate::db::has_index(db, API_KEYS_TABLE, MASTER_MARKER_INDEX).await? {
            return Err(MasterPinError::MissingConstraint);
        }

        let id = self.resolve_inner(db).await?;
        let _ = self.cell.set(id);

        let pinned = self.cell.get().copied().unwrap_or(id);
        tracing::info!(master_key_id = %pinned, "Master key identity pinned for this process.");
        Ok(pinned)
    }

    /// The pinned id, resolving it from the database on first use.
    pub async fn resolve(&self, db: &DatabaseConnection) -> Option<Uuid> {
        if let Some(id) = self.cell.get() {
            return Some(*id);
        }
        match self.resolve_inner(db).await {
            Ok(id) => {
                let _ = self.cell.set(id);
                self.cell.get().copied()
            }
            Err(e) => {
                tracing::warn!("Master key identity is not established: {e}");
                None
            }
        }
    }

    async fn resolve_inner(&self, db: &DatabaseConnection) -> Result<Uuid, MasterPinError> {
        let masters =
            ApiKey::find().filter(api_key::Column::IsMaster.eq(true)).all(db).await?;

        match masters.len() {
            0 => Err(MasterPinError::NoMaster),
            1 => Ok(masters[0].id),
            _ => Err(MasterPinError::Duplicates(masters.iter().map(|k| k.id).collect())),
        }
    }

    /// Applies the pin to a freshly authenticated key record. This is the single choke point for
    /// the whole guarantee: downstream code reads `key.is_master`, and a key that is not the
    /// pinned Master no longer says it is.
    pub async fn authenticate(&self, db: &DatabaseConnection, key: &mut api_key::Model) {
        if !key.is_master {
            return;
        }

        match self.resolve(db).await {
            Some(pinned) if pinned == key.id => {}
            Some(pinned) => {
                tracing::error!(
                    key = %key.prefix,
                    claimed_id = %key.id,
                    pinned_master = %pinned,
                    "TAMPER: a key carries is_master = true but is not the master this process \
                     pinned at boot. Treating it as an ordinary key."
                );
                key.is_master = false;
            }
            None => {
                tracing::error!(
                    key = %key.prefix,
                    claimed_id = %key.id,
                    "A key carries is_master = true but this process has no pinned master. \
                     Treating it as an ordinary key."
                );
                key.is_master = false;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pinned_cell_reports_its_id_without_a_database() {
        let id = Uuid::new_v4();
        let pin = MasterPin::pinned_to(id);
        assert_eq!(pin.get(), Some(id));
    }

    #[test]
    fn a_fresh_pin_is_unresolved() {
        assert_eq!(MasterPin::new().get(), None);
    }

    #[test]
    fn every_failure_names_a_remedy() {
        assert!(MasterPinError::NoMaster.to_string().contains("restart"));
        let dupes = MasterPinError::Duplicates(vec![Uuid::nil(), Uuid::max()]);
        assert!(dupes.to_string().contains("UPDATE api_keys SET is_master = false"));
        assert!(MasterPinError::MissingConstraint.to_string().contains(MASTER_MARKER_INDEX));
    }
}
