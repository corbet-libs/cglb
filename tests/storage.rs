//! Real per-row CAS, rollback, ABA, isolation and independent SQL-pool tests.
use cglb::{Error, storage::*};
use crlt::{Config, Db, Migration};
fn key(id: &str) -> Key {
    Key::new("challenge", id)
}
fn change(id: &str, deadline: u64) -> Change {
    Change {
        key: key(id),
        record: Some(Record {
            value: vec![1, 2, 3],
            deadline,
        }),
    }
}
async fn database(url: &str) -> Db {
    let mut config = Config::new(url, "");
    config.max_connections = 4;
    let db = Db::open(config).await.unwrap();
    db.migrate(&[Migration::new(1, "global", SCHEMA)])
        .await
        .unwrap();
    db
}
async fn contract(store: impl Store) {
    let first = store.read(&[key("a"), key("b")]).await.unwrap();
    assert_eq!(first.revisions[&key("a")], 0);
    assert!(
        store
            .compare_exchange(&first, vec![change("a", 100), change("b", u64::MAX)])
            .await
            .is_err()
    );
    assert!(
        store
            .list("challenge", "", 10)
            .await
            .unwrap()
            .records
            .is_empty()
    );
    store
        .compare_exchange(&first, vec![change("a", 100), change("b", 101)])
        .await
        .unwrap();
    assert!(matches!(
        store.compare_exchange(&first, vec![change("a", 100)]).await,
        Err(Error::Conflict)
    ));
    let a = store.read(&[key("a")]).await.unwrap();
    let b = store.read(&[key("b")]).await.unwrap();
    store
        .compare_exchange(&b, vec![change("b", 102)])
        .await
        .unwrap();
    store
        .compare_exchange(&a, vec![change("a", 101)])
        .await
        .unwrap();
    assert_eq!(
        store.list("challenge", "a", 1).await.unwrap().records.len(),
        1
    );
    assert!(store.expired(101, 10).await.unwrap().records.is_empty());
    assert_eq!(store.expired(102, 10).await.unwrap().records.len(), 1);
    let before_delete = store.read(&[key("a")]).await.unwrap();
    store
        .compare_exchange(
            &before_delete,
            vec![Change {
                key: key("a"),
                record: None,
            }],
        )
        .await
        .unwrap();
    let deleted = store.read(&[key("a")]).await.unwrap();
    assert!(deleted.records.is_empty());
    assert!(deleted.revisions[&key("a")] > before_delete.revisions[&key("a")]);
    store
        .compare_exchange(&deleted, vec![change("a", 100)])
        .await
        .unwrap();
    assert!(matches!(
        store
            .compare_exchange(&before_delete, vec![change("a", 105)])
            .await,
        Err(Error::Conflict)
    ));
    // A write cannot smuggle an unobserved key into a batch.
    assert!(
        store
            .compare_exchange(&deleted, vec![change("unread", 1)])
            .await
            .is_err()
    );
}
#[tokio::test]
async fn memory_rows_have_independent_revisions_and_no_aba() {
    contract(MemoryStore::new("global").unwrap()).await;
}
#[tokio::test]
async fn sql_rows_persist_with_indexed_reads_and_no_aba() {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("file://{}", dir.path().join("global.db").display());
    let db = database(&url).await;
    let store = LibsqlStore::new(&db, "global").unwrap();
    contract(store.clone()).await;
    store.check_query_plans().await.unwrap();
    assert!(
        LibsqlStore::new(&db, "other")
            .unwrap()
            .list("challenge", "", 10)
            .await
            .unwrap()
            .records
            .is_empty()
    );
    let before = store.read(&[key("a")]).await.unwrap().revisions;
    drop(store);
    drop(db);
    let db = database(&url).await;
    let store = LibsqlStore::new(&db, "global").unwrap();
    assert_eq!(before, store.read(&[key("a")]).await.unwrap().revisions);
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unrelated_pools_both_commit_but_same_person_has_one_winner() {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("file://{}", dir.path().join("race.db").display());
    let db_a = database(&url).await;
    let db_b = database(&url).await;
    let a = LibsqlStore::new(&db_a, "global").unwrap();
    let b = LibsqlStore::new(&db_b, "global").unwrap();
    let ra = a.read(&[key("a")]).await.unwrap();
    let rb = b.read(&[key("b")]).await.unwrap();
    let (x, y) = tokio::join!(
        a.compare_exchange(&ra, vec![change("a", 100)]),
        b.compare_exchange(&rb, vec![change("b", 100)])
    );
    assert!(x.is_ok() && y.is_ok());
    let ra = a.read(&[key("a")]).await.unwrap();
    let rb = b.read(&[key("a")]).await.unwrap();
    let (x, y) = tokio::join!(
        a.compare_exchange(&ra, vec![change("a", 101)]),
        b.compare_exchange(&rb, vec![change("a", 102)])
    );
    assert_eq!(usize::from(x.is_ok()) + usize::from(y.is_ok()), 1);
    let writer = db_a.community("global").unwrap().tx().await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), a.read(&[key("b")]))
        .await
        .unwrap()
        .unwrap();
    drop(writer);
}

async fn bounded_expiry_selects_the_oldest_real_rows(store: impl Store) {
    let keys = [
        key("a-later"),
        key("z-earlier"),
        Key::new("person", "other"),
    ];
    let observed = store.read(&keys).await.unwrap();
    assert!(matches!(
        store
            .compare_exchange(
                &observed,
                vec![change("a-later", 200), change("a-later", 201)]
            )
            .await,
        Err(Error::Conflict)
    ));
    assert!(store.read(&keys).await.unwrap().records.is_empty());
    store
        .compare_exchange(
            &observed,
            vec![
                change("a-later", 200),
                change("z-earlier", 100),
                Change {
                    key: keys[2].clone(),
                    record: Some(Record {
                        value: vec![9],
                        deadline: 1,
                    }),
                },
            ],
        )
        .await
        .unwrap();
    assert!(store.expired(300, 0).await.unwrap().records.is_empty());
    let oldest = store.expired(300, 1).await.unwrap();
    assert_eq!(oldest.records.keys().collect::<Vec<_>>(), vec![&keys[1]]);
    assert_eq!(oldest.revisions.len(), 1);
    assert!(store.expired(100, 10).await.unwrap().records.is_empty());
    assert_eq!(
        store
            .list("challenge", "a-later", 10)
            .await
            .unwrap()
            .records
            .len(),
        1
    );
}

#[tokio::test]
async fn actual_memory_expiry_order_matches_the_storage_contract() {
    bounded_expiry_selects_the_oldest_real_rows(MemoryStore::new("global").unwrap()).await;
}

#[tokio::test]
async fn actual_sql_expiry_order_matches_the_storage_contract() {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("file://{}", dir.path().join("expiry.db").display());
    let db = database(&url).await;
    bounded_expiry_selects_the_oldest_real_rows(LibsqlStore::new(&db, "global").unwrap()).await;
}

#[tokio::test]
async fn actual_imported_row_types_and_revision_limits_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("file://{}", dir.path().join("import.db").display());
    let db = Db::open(Config::new(url, "")).await.unwrap();
    let schema = SCHEMA
        .replace("CHECK(revision > 0)", "")
        .replace("CHECK(deadline >= 0)", "");
    db.migrate(&[Migration::new(1, "import", &schema)])
        .await
        .unwrap();
    let store = LibsqlStore::new(&db, "global").unwrap();
    let initial = store.read(&[key("bad")]).await.unwrap();
    store
        .compare_exchange(&initial, vec![change("bad", 10)])
        .await
        .unwrap();
    let raw = db.community("global").unwrap();
    for (revision, value, deadline) in [
        (
            crlt::Value::Text("wrong".into()),
            crlt::Value::Blob(vec![1]),
            crlt::Value::Integer(10),
        ),
        (
            crlt::Value::Integer(0),
            crlt::Value::Blob(vec![1]),
            crlt::Value::Integer(10),
        ),
        (
            crlt::Value::Integer(1),
            crlt::Value::Integer(9),
            crlt::Value::Integer(10),
        ),
        (
            crlt::Value::Integer(1),
            crlt::Value::Blob(vec![1]),
            crlt::Value::Text("wrong".into()),
        ),
        (
            crlt::Value::Integer(1),
            crlt::Value::Blob(vec![1]),
            crlt::Value::Integer(-1),
        ),
    ] {
        raw.execute("UPDATE cglb_record SET revision=?1, value=?2, deadline=?3 WHERE bucket='challenge' AND entry_key='bad'", crlt::params![revision, value, deadline]).await.unwrap();
        assert!(matches!(
            store.read(&[key("bad")]).await,
            Err(Error::Storage)
        ));
        assert!(matches!(
            store.list("challenge", "", 10).await,
            Err(Error::Storage)
        ));
    }
    raw.execute("UPDATE cglb_record SET revision=?1, value=?2, deadline=10 WHERE bucket='challenge' AND entry_key='bad'", crlt::params![i64::MAX, vec![1u8]]).await.unwrap();
    let maximum = store.read(&[key("bad")]).await.unwrap();
    assert!(matches!(
        store
            .compare_exchange(&maximum, vec![change("bad", 11)])
            .await,
        Err(Error::Exhausted)
    ));
    assert_eq!(
        store.read(&[key("bad")]).await.unwrap().revisions[&key("bad")],
        i64::MAX
    );
    assert!(matches!(
        store.expired(u64::MAX, 1).await,
        Err(Error::InvalidTime)
    ));
}
