use cglb::{
    Error,
    crlt::{Config, Db, Migration},
    storage::*,
};

fn change(id: &str, deadline: u64) -> Change {
    Change {
        key: Key::new("challenge", id),
        record: Some(Record {
            value: vec![1, 2, 3],
            deadline,
        }),
    }
}
async fn contract(store: impl Store) {
    let key = Key::new("challenge", "a");
    let first = store.read(std::slice::from_ref(&key)).await.unwrap();
    assert_eq!(first.revision, 0);
    store
        .compare_exchange(0, vec![change("a", 100), change("b", 101)])
        .await
        .unwrap();
    let read = store.read(std::slice::from_ref(&key)).await.unwrap();
    assert_eq!(read.records[&key].value, vec![1, 2, 3]);
    assert!(matches!(
        store.compare_exchange(0, vec![change("c", 1)]).await,
        Err(Error::Conflict)
    ));
    assert_eq!(
        store.list("challenge", "a", 1).await.unwrap().records.len(),
        1
    );
    assert!(store.expired(100, 5).await.unwrap().records.is_empty());
    assert_eq!(store.expired(101, 5).await.unwrap().records.len(), 1);
    store
        .compare_exchange(
            read.revision,
            vec![Change {
                key: key.clone(),
                record: None,
            }],
        )
        .await
        .unwrap();
    assert!(store.read(&[key]).await.unwrap().records.is_empty());
}
async fn db(url: &str) -> Db {
    let db = Db::open(Config::new(url, "")).await.unwrap();
    let migrations = [
        Migration::new(1, "global", SCHEMA),
        Migration::new(2, "signing", cglb::csgn::SCHEMA),
    ];
    assert_eq!(db.migrate(&migrations).await.unwrap(), 2);
    assert_eq!(db.migrate(&migrations).await.unwrap(), 0);
    db
}
#[tokio::test]
async fn memory_contract() {
    contract(MemoryStore::new("global").unwrap()).await;
}
#[tokio::test]
async fn libsql_contract_indexes_reopen_and_isolation() {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("file://{}", dir.path().join("global.db").display());
    let database = db(&url).await;
    let store = LibsqlStore::new(&database, "global").unwrap();
    contract(store.clone()).await;
    store.check_query_plans().await.unwrap();
    let other = LibsqlStore::new(&database, "community").unwrap();
    assert!(
        other
            .list("challenge", "", 10)
            .await
            .unwrap()
            .records
            .is_empty()
    );
    assert!(other.expired(1000, 10).await.unwrap().records.is_empty());
    drop(store);
    drop(database);
    let reopened = Db::open(Config::new(url, "")).await.unwrap();
    reopened
        .migrate(&[
            Migration::new(1, "global", SCHEMA),
            Migration::new(2, "signing", cglb::csgn::SCHEMA),
        ])
        .await
        .unwrap();
    let store = LibsqlStore::new(&reopened, "global").unwrap();
    assert_eq!(
        store.list("challenge", "", 10).await.unwrap().records.len(),
        1
    );
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn independent_pools_cannot_commit_the_same_revision() {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("file://{}", dir.path().join("race.db").display());
    let a = db(&url).await;
    let b = Db::open(Config::new(url, "")).await.unwrap();
    b.migrate(&[
        Migration::new(1, "global", SCHEMA),
        Migration::new(2, "signing", cglb::csgn::SCHEMA),
    ])
    .await
    .unwrap();
    let a = LibsqlStore::new(&a, "global").unwrap();
    let b = LibsqlStore::new(&b, "global").unwrap();
    let (x, y) = tokio::join!(
        a.compare_exchange(0, vec![change("a", 1)]),
        b.compare_exchange(0, vec![change("b", 1)])
    );
    assert_eq!(usize::from(x.is_ok()) + usize::from(y.is_ok()), 1);
    assert!(matches!(x, Err(Error::Conflict)) || matches!(y, Err(Error::Conflict)));
    assert_eq!(a.list("challenge", "", 10).await.unwrap().records.len(), 1);
}
#[tokio::test]
async fn failed_batch_rolls_back_every_change_and_revision() {
    let dir = tempfile::tempdir().unwrap();
    let database = db(&format!(
        "file://{}",
        dir.path().join("rollback.db").display()
    ))
    .await;
    let store = LibsqlStore::new(&database, "global").unwrap();
    assert!(
        store
            .compare_exchange(0, vec![change("valid", 1), change("overflow", u64::MAX)])
            .await
            .is_err()
    );
    let read = store.list("challenge", "", 10).await.unwrap();
    assert_eq!(read.revision, 0);
    assert!(read.records.is_empty());
    store
        .compare_exchange(0, vec![change("valid", 1)])
        .await
        .unwrap();
}
#[tokio::test]
async fn optional_real_turso() {
    let (Ok(url), Ok(token)) = (std::env::var("TURSO_URL"), std::env::var("TURSO_TOKEN")) else {
        eprintln!("SKIP live Turso: both environment credentials are required");
        return;
    };
    if url.is_empty() || token.is_empty() {
        eprintln!("SKIP live Turso: empty credential");
        return;
    }
    let database = Db::open(Config::new(url, token)).await.unwrap();
    database
        .migrate(&[
            Migration::new(1, "global", SCHEMA),
            Migration::new(2, "signing", cglb::csgn::SCHEMA),
        ])
        .await
        .unwrap();
    use cglb::cpsd::rand::RngCore;
    let scope = format!("test-{:016x}", cglb::cpsd::rand::rngs::OsRng.next_u64());
    let store = LibsqlStore::new(&database, &scope).unwrap();
    contract(store.clone()).await;
    store.check_query_plans().await.unwrap();
    let rows = store.list("challenge", "", 10).await.unwrap();
    store
        .compare_exchange(
            rows.revision,
            rows.records
                .into_keys()
                .map(|key| Change { key, record: None })
                .collect(),
        )
        .await
        .unwrap();
    database
        .community(scope)
        .unwrap()
        .execute("DELETE FROM cglb_revision WHERE singleton = 1", ())
        .await
        .unwrap();
}
