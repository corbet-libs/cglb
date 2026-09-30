//! Fixed-scope, revisioned persistence. Backends never decide identity policy.
use crate::{Error, Result};
use std::{
    collections::BTreeMap,
    future::Future,
    sync::{Arc, Mutex},
};

/// Composite key in the service's private namespace.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Key {
    /// Fixed internal record class.
    pub bucket: String,
    /// Opaque identifier within that class.
    pub id: String,
}
impl Key {
    /// Construct a storage key. Only trusted facade code selects keys.
    pub fn new(bucket: &str, id: impl Into<String>) -> Self {
        Self {
            bucket: bucket.into(),
            id: id.into(),
        }
    }
}
/// Current state bytes; never raw gate input, passport bytes or secret keys.
#[derive(Clone)]
pub struct Record {
    /// JSON-encoded current state.
    pub value: Vec<u8>,
    /// Pending challenge deadline; zero for records without expiry.
    pub deadline: u64,
}
/// Consistent read and its compare-and-exchange revision.
#[derive(Clone, Default)]
pub struct ReadSet {
    /// Monotonic scope revision, zero before first write.
    pub revision: i64,
    /// Present records; requested missing keys are absent.
    pub records: BTreeMap<Key, Record>,
}
/// One atomic replacement or deletion.
pub struct Change {
    /// Record to replace.
    pub key: Key,
    /// None deletes the record.
    pub record: Option<Record>,
}
/// Storage capability for exactly one global scope.
///
/// Reads must be consistent. CAS must atomically check the scope revision and
/// apply the entire batch, incrementing that revision once. It must never wrap,
/// reset, partially apply, log values or return success before commit. An
/// uncertain commit returns an error. Implementations and callers are trusted.
pub trait Store: Send + Sync {
    /// Fixed namespace, never chosen from a member request.
    fn scope(&self) -> &str;
    /// Fetch a bounded collection of keys in one consistent snapshot.
    fn read(&self, keys: &[Key]) -> impl Future<Output = Result<ReadSet>> + Send;
    /// Read one bucket in key order, exclusive of `after`, at most `limit` rows.
    fn list(
        &self,
        bucket: &str,
        after: &str,
        limit: u32,
    ) -> impl Future<Output = Result<ReadSet>> + Send;
    /// Read expired pending challenges, at most `limit` rows.
    fn expired(&self, now: u64, limit: u32) -> impl Future<Output = Result<ReadSet>> + Send;
    /// Apply a batch only if the revision still equals `expected`.
    fn compare_exchange(
        &self,
        expected: i64,
        changes: Vec<Change>,
    ) -> impl Future<Output = Result<()>> + Send;
}

/// Real volatile store; clones share state, fresh instances are isolated.
#[derive(Clone)]
pub struct MemoryStore {
    scope: String,
    state: Arc<Mutex<ReadSet>>,
}
impl MemoryStore {
    /// Create a store for an opaque global scope.
    pub fn new(scope: &str) -> Result<Self> {
        crate::validate_id(scope)?;
        Ok(Self {
            scope: scope.into(),
            state: Arc::default(),
        })
    }
    fn select(&self, predicate: impl Fn(&Key, &Record) -> bool, limit: usize) -> Result<ReadSet> {
        let state = self.state.lock().map_err(|_| Error::Storage)?;
        Ok(ReadSet {
            revision: state.revision,
            records: state
                .records
                .iter()
                .filter(|(k, v)| predicate(k, v))
                .take(limit)
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        })
    }
}
impl Store for MemoryStore {
    fn scope(&self) -> &str {
        &self.scope
    }
    async fn read(&self, keys: &[Key]) -> Result<ReadSet> {
        self.select(|k, _| keys.contains(k), usize::MAX)
    }
    async fn list(&self, bucket: &str, after: &str, limit: u32) -> Result<ReadSet> {
        self.select(
            |k, _| k.bucket == bucket && k.id.as_str() > after,
            limit as usize,
        )
    }
    async fn expired(&self, now: u64, limit: u32) -> Result<ReadSet> {
        self.select(
            |k, v| k.bucket == "challenge" && v.deadline < now,
            limit as usize,
        )
    }
    async fn compare_exchange(&self, expected: i64, changes: Vec<Change>) -> Result<()> {
        let mut state = self.state.lock().map_err(|_| Error::Storage)?;
        if state.revision != expected {
            return Err(Error::Conflict);
        }
        let next = expected.checked_add(1).ok_or(Error::Exhausted)?;
        for change in changes {
            if let Some(record) = change.record {
                state.records.insert(change.key, record);
            } else {
                state.records.remove(&change.key);
            }
        }
        state.revision = next;
        Ok(())
    }
}

/// Append to the service-owned crlt migration history, followed by csgn::SCHEMA.
pub const SCHEMA: &str = "
CREATE TABLE cglb_revision (
 community_id TEXT NOT NULL, singleton INTEGER NOT NULL CHECK(singleton = 1),
 revision INTEGER NOT NULL CHECK(revision > 0),
 PRIMARY KEY(community_id, singleton)
) WITHOUT ROWID;
CREATE TABLE cglb_record (
 community_id TEXT NOT NULL, bucket TEXT NOT NULL, entry_key TEXT NOT NULL,
 value BLOB NOT NULL, deadline INTEGER NOT NULL CHECK(deadline >= 0),
 PRIMARY KEY(community_id, bucket, entry_key)
) WITHOUT ROWID;
CREATE INDEX cglb_deadline ON cglb_record(community_id, bucket, deadline, entry_key);
";
const REV: &str = "SELECT revision FROM cglb_revision WHERE singleton = 1";
const GET: &str = "SELECT value, deadline FROM cglb_record WHERE bucket = ?1 AND entry_key = ?2";
const LIST: &str = "SELECT entry_key, value, deadline FROM cglb_record WHERE bucket = ?1 AND entry_key > ?2 ORDER BY entry_key LIMIT ?3";
const EXPIRED: &str = "SELECT entry_key, value, deadline FROM cglb_record WHERE bucket = ?1 AND deadline < ?2 ORDER BY deadline, entry_key LIMIT ?3";
const DELETE: &str = "DELETE FROM cglb_record WHERE bucket = ?1 AND entry_key = ?2";
const INSERT: &str =
    "INSERT INTO cglb_record(bucket, entry_key, value, deadline) VALUES (?1, ?2, ?3, ?4)";
const ADVANCE: &str =
    "UPDATE cglb_revision SET revision = ?1 WHERE singleton = 1 AND revision = ?2";
const CREATE_REV: &str = "INSERT INTO cglb_revision(singleton, revision) VALUES (1, ?1)";

/// Durable adapter over the pinned crlt facade and official libSQL client.
#[derive(Clone)]
pub struct LibsqlStore {
    scope: String,
    db: crlt::Community,
}
impl LibsqlStore {
    /// Bind a service-selected scope. Migrations must already be installed.
    pub fn new(db: &crlt::Db, scope: &str) -> Result<Self> {
        crate::validate_id(scope)?;
        Ok(Self {
            scope: scope.into(),
            db: db.community(scope).map_err(|_| Error::Storage)?,
        })
    }
    async fn revision(tx: &mut crlt::Transaction) -> Result<i64> {
        let rows = tx.query(REV, ()).await.map_err(|_| Error::Storage)?;
        rows.first()
            .map(|r| r.get_i64(0).map_err(|_| Error::Storage))
            .unwrap_or(Ok(0))
    }
    async fn select(&self, sql: &str, params: Vec<crlt::Value>, bucket: &str) -> Result<ReadSet> {
        let mut tx = self.db.tx().await.map_err(|_| Error::Storage)?;
        let revision = Self::revision(&mut tx).await?;
        let mut records = BTreeMap::new();
        for row in tx.query(sql, params).await.map_err(|_| Error::Storage)? {
            let key = Key::new(bucket, row.get_str(0).map_err(|_| Error::Storage)?);
            records.insert(key, decode(&row, 1)?);
        }
        tx.commit().await.map_err(|_| Error::Storage)?;
        Ok(ReadSet { revision, records })
    }
    /// Check every adapter statement against the real database query planner.
    pub async fn check_query_plans(&self) -> Result<()> {
        use crlt::Value;
        let text = || Value::Text("probe".into());
        for (sql, args) in [
            (REV, vec![]),
            (GET, vec![text(), text()]),
            (LIST, vec![text(), text(), Value::Integer(1)]),
            (EXPIRED, vec![text(), Value::Integer(1), Value::Integer(1)]),
            (DELETE, vec![text(), text()]),
            (
                INSERT,
                vec![text(), text(), Value::Blob(vec![]), Value::Integer(0)],
            ),
            (ADVANCE, vec![Value::Integer(2), Value::Integer(1)]),
            (CREATE_REV, vec![Value::Integer(1)]),
        ] {
            self.db
                .explain(sql, args)
                .await
                .map_err(|_| Error::Storage)?
                .assert_indexed()
                .map_err(|_| Error::Storage)?;
        }
        Ok(())
    }
}
fn decode(row: &crlt::Row, offset: usize) -> Result<Record> {
    let crlt::Value::Blob(value) = row.get_value(offset).map_err(|_| Error::Storage)? else {
        return Err(Error::Storage);
    };
    let deadline = u64::try_from(row.get_i64(offset + 1).map_err(|_| Error::Storage)?)
        .map_err(|_| Error::Storage)?;
    Ok(Record {
        value: value.clone(),
        deadline,
    })
}
impl Store for LibsqlStore {
    fn scope(&self) -> &str {
        &self.scope
    }
    async fn read(&self, keys: &[Key]) -> Result<ReadSet> {
        let mut tx = self.db.tx().await.map_err(|_| Error::Storage)?;
        let revision = Self::revision(&mut tx).await?;
        let mut records = BTreeMap::new();
        for key in keys {
            let rows = tx
                .query(GET, crlt::params![key.bucket.clone(), key.id.clone()])
                .await
                .map_err(|_| Error::Storage)?;
            if let Some(row) = rows.first() {
                records.insert(key.clone(), decode(row, 0)?);
            }
        }
        tx.commit().await.map_err(|_| Error::Storage)?;
        Ok(ReadSet { revision, records })
    }
    async fn list(&self, bucket: &str, after: &str, limit: u32) -> Result<ReadSet> {
        self.select(
            LIST,
            vec![
                bucket.to_owned().into(),
                after.to_owned().into(),
                i64::from(limit).into(),
            ],
            bucket,
        )
        .await
    }
    async fn expired(&self, now: u64, limit: u32) -> Result<ReadSet> {
        let now = i64::try_from(now).map_err(|_| Error::InvalidTime)?;
        self.select(
            EXPIRED,
            vec![
                "challenge".to_owned().into(),
                now.into(),
                i64::from(limit).into(),
            ],
            "challenge",
        )
        .await
    }
    async fn compare_exchange(&self, expected: i64, changes: Vec<Change>) -> Result<()> {
        let mut tx = self.db.tx().await.map_err(|_| Error::Storage)?;
        if Self::revision(&mut tx).await? != expected {
            return Err(Error::Conflict);
        }
        let next = expected.checked_add(1).ok_or(Error::Exhausted)?;
        if expected == 0 {
            tx.execute(CREATE_REV, [next])
                .await
                .map_err(|_| Error::Storage)?;
        } else {
            tx.execute(ADVANCE, [next, expected])
                .await
                .map_err(|_| Error::Storage)?;
        }
        for change in changes {
            tx.execute(
                DELETE,
                crlt::params![change.key.bucket.clone(), change.key.id.clone()],
            )
            .await
            .map_err(|_| Error::Storage)?;
            if let Some(record) = change.record {
                let deadline = i64::try_from(record.deadline).map_err(|_| Error::InvalidTime)?;
                tx.execute(
                    INSERT,
                    crlt::params![change.key.bucket, change.key.id, record.value, deadline],
                )
                .await
                .map_err(|_| Error::Storage)?;
            }
        }
        tx.commit().await.map_err(|_| Error::Storage)
    }
}
