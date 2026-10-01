//! Fixed-scope persistence with independent revisions for each person/key.
use crate::{Error, Result};
use std::{
    collections::BTreeMap,
    future::Future,
    sync::{Arc, Mutex},
};

/// Composite key selected only by trusted facade code.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Key {
    /// Internal record class.
    pub bucket: String,
    /// Opaque identifier within the class.
    pub id: String,
}
impl Key {
    /// Construct a storage key.
    pub fn new(bucket: &str, id: impl Into<String>) -> Self {
        Self {
            bucket: bucket.into(),
            id: id.into(),
        }
    }
}
/// Current typed facade state; never raw provider input or a passport.
#[derive(Clone)]
pub struct Record {
    /// JSON state bytes.
    pub value: Vec<u8>,
    /// Protocol challenge deadline; zero for other records.
    pub deadline: u64,
}
/// Observed per-key revisions. Missing keys have revision zero; deleted keys
/// retain a revision tombstone, preventing delete/recreate ABA.
#[derive(Clone, Default)]
pub struct ReadSet {
    /// Every observed key, including missing records.
    pub revisions: BTreeMap<Key, i64>,
    /// Present records.
    pub records: BTreeMap<Key, Record>,
}
/// One atomic replacement or deletion.
pub struct Change {
    /// Key that must have been observed in the supplied ReadSet.
    pub key: Key,
    /// New state, or deletion.
    pub record: Option<Record>,
}
/// Trusted storage capability for a fixed global scope. compare_exchange checks
/// every supplied revision and changes only explicitly observed keys atomically.
/// Unrelated people never invalidate an observation. Revisions never reset.
pub trait Store: Send + Sync {
    /// Service-selected namespace.
    fn scope(&self) -> &str;
    /// Read keys and their individual revisions; writes validate the whole read set.
    fn read(&self, keys: &[Key]) -> impl Future<Output = Result<ReadSet>> + Send;
    /// Present bucket entries, ordered by key with an exclusive cursor.
    fn list(
        &self,
        bucket: &str,
        after: &str,
        limit: u32,
    ) -> impl Future<Output = Result<ReadSet>> + Send;
    /// Bounded expired challenge rows, ordered by deadline and key.
    fn expired(&self, now: u64, limit: u32) -> impl Future<Output = Result<ReadSet>> + Send;
    /// Compare the observed keys and atomically apply the complete batch.
    fn compare_exchange(
        &self,
        expected: &ReadSet,
        changes: Vec<Change>,
    ) -> impl Future<Output = Result<()>> + Send;
}
type Rows = BTreeMap<Key, (i64, Option<Record>)>;
/// Volatile store; clones share actual rows and revisions.
#[derive(Clone)]
pub struct MemoryStore {
    scope: String,
    state: Arc<Mutex<Rows>>,
}
impl MemoryStore {
    /// Create a fixed namespace.
    pub fn new(scope: &str) -> Result<Self> {
        crate::validate_id(scope)?;
        Ok(Self {
            scope: scope.into(),
            state: Arc::default(),
        })
    }
    fn select(&self, predicate: impl Fn(&Key, &Record) -> bool, limit: usize) -> Result<ReadSet> {
        let state = self.state.lock().map_err(|_| Error::Storage)?;
        let mut read = ReadSet::default();
        for (key, revision, record) in state
            .iter()
            .filter_map(|(key, (revision, record))| {
                record
                    .as_ref()
                    .filter(|record| predicate(key, record))
                    .map(|record| (key, revision, record))
            })
            .take(limit)
        {
            read.revisions.insert(key.clone(), *revision);
            read.records.insert(key.clone(), record.clone());
        }
        Ok(read)
    }
}
fn validate(expected: &ReadSet, changes: &[Change]) -> Result<()> {
    let mut seen = std::collections::BTreeSet::new();
    for change in changes {
        if !seen.insert(&change.key) || !expected.revisions.contains_key(&change.key) {
            return Err(Error::Conflict);
        }
        expected.revisions[&change.key]
            .checked_add(1)
            .ok_or(Error::Exhausted)?;
        if change
            .record
            .as_ref()
            .is_some_and(|r| r.deadline > i64::MAX as u64)
        {
            return Err(Error::InvalidTime);
        }
    }
    Ok(())
}
impl Store for MemoryStore {
    fn scope(&self) -> &str {
        &self.scope
    }
    async fn read(&self, keys: &[Key]) -> Result<ReadSet> {
        let state = self.state.lock().map_err(|_| Error::Storage)?;
        let mut read = ReadSet::default();
        for key in keys {
            let (revision, record) = state.get(key).cloned().unwrap_or((0, None));
            read.revisions.insert(key.clone(), revision);
            if let Some(record) = record {
                read.records.insert(key.clone(), record);
            }
        }
        Ok(read)
    }
    async fn list(&self, bucket: &str, after: &str, limit: u32) -> Result<ReadSet> {
        self.select(
            |k, _| k.bucket == bucket && k.id.as_str() > after,
            limit as usize,
        )
    }
    async fn expired(&self, now: u64, limit: u32) -> Result<ReadSet> {
        let state = self.state.lock().map_err(|_| Error::Storage)?;
        let mut expired: Vec<_> = state
            .iter()
            .filter_map(|(key, (revision, record))| {
                record.as_ref()
                    .filter(|record| key.bucket == "challenge" && record.deadline < now)
                    .map(|record| (key, *revision, record))
            })
            .collect();
        expired.sort_unstable_by(|(left_key, _, left), (right_key, _, right)| {
            (left.deadline, left_key).cmp(&(right.deadline, right_key))
        });
        let mut read = ReadSet::default();
        for (key, revision, record) in expired.into_iter().take(limit as usize) {
            read.revisions.insert(key.clone(), revision);
            read.records.insert(key.clone(), record.clone());
        }
        Ok(read)
    }
    async fn compare_exchange(&self, expected: &ReadSet, changes: Vec<Change>) -> Result<()> {
        validate(expected, &changes)?;
        let mut state = self.state.lock().map_err(|_| Error::Storage)?;
        if expected
            .revisions
            .iter()
            .any(|(key, rev)| state.get(key).map_or(0, |(r, _)| *r) != *rev)
        {
            return Err(Error::Conflict);
        }
        for change in changes {
            let next = expected.revisions[&change.key] + 1;
            state.insert(change.key, (next, change.record));
        }
        Ok(())
    }
}
/// New installations append this schema and the csgn/cpsd leaf schemas to their
/// service-owned migration list. Existing installations need an explicit upgrade.
pub const SCHEMA: &str = "
CREATE TABLE cglb_record (
 community_id TEXT NOT NULL, bucket TEXT NOT NULL, entry_key TEXT NOT NULL,
 revision INTEGER NOT NULL CHECK(revision > 0), value BLOB,
 deadline INTEGER NOT NULL CHECK(deadline >= 0),
 PRIMARY KEY(community_id,bucket,entry_key)
) WITHOUT ROWID;
CREATE INDEX cglb_deadline ON cglb_record(community_id,bucket,deadline,entry_key);
";
const GET: &str =
    "SELECT revision, value, deadline FROM cglb_record WHERE bucket = ?1 AND entry_key = ?2";
const LIST: &str = "SELECT entry_key, revision, value, deadline FROM cglb_record WHERE bucket = ?1 AND entry_key > ?2 AND value IS NOT NULL ORDER BY entry_key LIMIT ?3";
const EXPIRED: &str = "SELECT entry_key, revision, value, deadline FROM cglb_record WHERE bucket = ?1 AND deadline < ?2 AND value IS NOT NULL ORDER BY deadline, entry_key LIMIT ?3";
const INSERT: &str = "INSERT INTO cglb_record(bucket, entry_key, revision, value, deadline) VALUES (?1, ?2, ?3, ?4, ?5)";
const UPDATE: &str = "UPDATE cglb_record SET revision = ?1, value = ?2, deadline = ?3 WHERE bucket = ?4 AND entry_key = ?5 AND revision = ?6";
/// Durable per-row revisions over the service's crlt pool.
#[derive(Clone)]
pub struct LibsqlStore {
    scope: String,
    db: crlt::Community,
}
impl LibsqlStore {
    /// Bind the already migrated global database.
    pub fn new(db: &crlt::Db, scope: &str) -> Result<Self> {
        crate::validate_id(scope)?;
        Ok(Self {
            scope: scope.into(),
            db: db.community(scope).map_err(|_| Error::Storage)?,
        })
    }
    async fn select(&self, sql: &str, args: Vec<crlt::Value>, bucket: &str) -> Result<ReadSet> {
        let mut read = ReadSet::default();
        for row in self.db.query(sql, args).await.map_err(|_| Error::Storage)? {
            let key = Key::new(bucket, row.get_str(0).map_err(|_| Error::Storage)?);
            add(&mut read, key, &row, 1)?;
        }
        Ok(read)
    }
    /// Check every statement through the actual query planner.
    pub async fn check_query_plans(&self) -> Result<()> {
        use crlt::Value;
        let text = || Value::Text("probe".into());
        for (sql, args) in [
            (GET, vec![text(), text()]),
            (LIST, vec![text(), text(), 1i64.into()]),
            (EXPIRED, vec![text(), 1i64.into(), 1i64.into()]),
            (
                INSERT,
                vec![
                    text(),
                    text(),
                    1i64.into(),
                    Value::Blob(vec![]),
                    0i64.into(),
                ],
            ),
            (
                UPDATE,
                vec![
                    2i64.into(),
                    Value::Null,
                    0i64.into(),
                    text(),
                    text(),
                    1i64.into(),
                ],
            ),
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
fn add(read: &mut ReadSet, key: Key, row: &crlt::Row, offset: usize) -> Result<()> {
    let revision = row.get_i64(offset).map_err(|_| Error::Storage)?;
    if revision <= 0 {
        return Err(Error::Storage);
    }
    read.revisions.insert(key.clone(), revision);
    match row.get_value(offset + 1).map_err(|_| Error::Storage)? {
        crlt::Value::Null => {}
        crlt::Value::Blob(value) => {
            let deadline = u64::try_from(row.get_i64(offset + 2).map_err(|_| Error::Storage)?)
                .map_err(|_| Error::Storage)?;
            read.records.insert(
                key,
                Record {
                    value: value.clone(),
                    deadline,
                },
            );
        }
        _ => return Err(Error::Storage),
    }
    Ok(())
}
impl Store for LibsqlStore {
    fn scope(&self) -> &str {
        &self.scope
    }
    async fn read(&self, keys: &[Key]) -> Result<ReadSet> {
        let mut read = ReadSet::default();
        // Point reads acquire no write transaction. A writer validates every
        // observed revision inside its one transaction before committing.
        for key in keys {
            let rows = self
                .db
                .query(GET, crlt::params![key.bucket.clone(), key.id.clone()])
                .await
                .map_err(|_| Error::Storage)?;
            if let Some(row) = rows.first() {
                add(&mut read, key.clone(), row, 0)?;
            } else {
                read.revisions.insert(key.clone(), 0);
            }
        }
        Ok(read)
    }
    async fn list(&self, bucket: &str, after: &str, limit: u32) -> Result<ReadSet> {
        self.select(
            LIST,
            vec![bucket.into(), after.into(), i64::from(limit).into()],
            bucket,
        )
        .await
    }
    async fn expired(&self, now: u64, limit: u32) -> Result<ReadSet> {
        let now = i64::try_from(now).map_err(|_| Error::InvalidTime)?;
        self.select(
            EXPIRED,
            vec!["challenge".into(), now.into(), i64::from(limit).into()],
            "challenge",
        )
        .await
    }
    async fn compare_exchange(&self, expected: &ReadSet, changes: Vec<Change>) -> Result<()> {
        validate(expected, &changes)?;
        let mut tx = self.db.tx().await.map_err(|_| Error::Storage)?;
        for (key, revision) in &expected.revisions {
            let rows = tx
                .query(GET, crlt::params![key.bucket.clone(), key.id.clone()])
                .await
                .map_err(|_| Error::Storage)?;
            let current = rows
                .first()
                .map(|r| r.get_i64(0).map_err(|_| Error::Storage))
                .transpose()?
                .unwrap_or(0);
            if current != *revision {
                return Err(Error::Conflict);
            }
        }
        for change in changes {
            let old = expected.revisions[&change.key];
            let (value, deadline) = change.record.map_or((crlt::Value::Null, 0), |r| {
                (crlt::Value::Blob(r.value), r.deadline as i64)
            });
            let affected = if old == 0 {
                tx.execute(
                    INSERT,
                    crlt::params![change.key.bucket, change.key.id, old + 1, value, deadline],
                )
                .await
            } else {
                tx.execute(
                    UPDATE,
                    crlt::params![
                        old + 1,
                        value,
                        deadline,
                        change.key.bucket,
                        change.key.id,
                        old
                    ],
                )
                .await
            }
            .map_err(|_| Error::Storage)?;
            if affected != 1 {
                return Err(Error::Conflict);
            }
        }
        tx.commit().await.map_err(|_| Error::Storage)
    }
}
