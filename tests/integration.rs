use tokio_postgres::config::{ChannelBinding, SslMode};
use tokio_postgres::Config;
use tokio_postgres_rustls::MakeRustlsConnect;

mod support;
use support::certstore::CertStore;
use support::docker::PostgresContainer;

#[tokio::test]
async fn ssl_user_without_client_cert_rejected() {
    let mut pg = PostgresContainer::new(
        "ssl-user-without-client-cert-rejected",
        "./tests/support/sql_setup.sh",
        "./tests/support/ca.crt",
        "./tests/support/server.crt",
        "./tests/support/server.key",
    )
    .await
    .expect("start postgres test container");

    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(CertStore::roots())
        .with_no_client_auth();
    let tls = MakeRustlsConnect::new(tls_config);

    let mut pg_config = Config::new();
    pg_config
        .host("localhost")
        .port(pg.port)
        .dbname("postgres")
        .user("ssl_user")
        .ssl_mode(SslMode::Prefer);

    let Err(err) = pg_config.connect(tls).await else {
        let _ = pg.cleanup().await;
        panic!("connect to postgres as ssl_user without client auth should fail");
    };

    if err.to_string() != "db error: FATAL: connection requires a valid client certificate" {
        let _ = pg.cleanup().await;
        panic!("connect to postgres as ssl_user without client auth failed with unexpected error: {:?}", err);
    }

    let _ = pg.cleanup().await;
}

#[tokio::test]
async fn ssl_user_ok() {
    let mut pg = PostgresContainer::new(
        "ssl-user-with-client-cert-ok",
        "./tests/support/sql_setup.sh",
        "./tests/support/ca.crt",
        "./tests/support/server.crt",
        "./tests/support/server.key",
    )
    .await
    .expect("start postgres test container");

    let certs = CertStore::sha256();
    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(certs.roots)
        .with_client_auth_cert(certs.client_certs, certs.client_key)
        .expect("build rustls client config");
    let tls = MakeRustlsConnect::new(tls_config);

    let mut pg_config = Config::new();
    pg_config
        .host("localhost")
        .port(pg.port)
        .dbname("postgres")
        .user("ssl_user")
        .ssl_mode(SslMode::Require);
    let (client, conn) = pg_config.connect(tls).await.expect("connect");
    tokio::spawn(async move { conn.await.map_err(|e| panic!("{:?}", e)) });

    let stmt = client.prepare("SELECT 1::INT4").await.expect("prepare");
    let rows = client.query(&stmt, &[]).await.expect("query");
    assert_eq!(1, rows.len());
    let res: i32 = (&rows[0]).get(0);
    assert_eq!(1, res);

    let _ = pg.cleanup().await;
}

#[tokio::test]
async fn scram_test_sha256_ok() {
    let mut pg = PostgresContainer::new(
        "scram-sha256",
        "./tests/support/sql_setup.sh",
        "./tests/support/ca.crt",
        "./tests/support/server.crt",
        "./tests/support/server.key",
    )
    .await
    .expect("start postgres test container");

    let certs = CertStore::sha256();
    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(certs.roots)
        .with_client_auth_cert(certs.client_certs, certs.client_key)
        .expect("build rustls client config");
    let tls = MakeRustlsConnect::new(tls_config);

    let mut pg_config = Config::new();
    pg_config
        .host("localhost")
        .port(pg.port)
        .dbname("postgres")
        .user("scram_user")
        .password("password")
        .ssl_mode(SslMode::Require)
        .channel_binding(ChannelBinding::Require);
    let (client, conn) = pg_config.connect(tls).await.expect("connect");
    tokio::spawn(async move { conn.await.map_err(|e| panic!("{:?}", e)) });

    let stmt = client.prepare("SELECT 1::INT4").await.expect("prepare");
    let rows = client.query(&stmt, &[]).await.expect("query");
    assert_eq!(1, rows.len());
    let res: i32 = (&rows[0]).get(0);
    assert_eq!(1, res);

    let _ = pg.cleanup().await;
}

#[tokio::test]
async fn scram_test_sha384_ok() {
    let mut pg = PostgresContainer::new(
        "scram-sha384",
        "./tests/support/sql_setup.sh",
        "./tests/support/ca.crt",
        "./tests/support/server_sha384.crt",
        "./tests/support/server.key",
    )
    .await
    .expect("start postgres test container");

    let certs = CertStore::sha384();
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(certs.roots)
        .with_client_auth_cert(certs.client_certs, certs.client_key)
        .expect("build rustls client config");
    let tls = MakeRustlsConnect::new(config);

    let mut pg_config = Config::new();
    pg_config
        .host("localhost")
        .port(pg.port)
        .dbname("postgres")
        .user("scram_user")
        .password("password")
        .ssl_mode(SslMode::Require)
        .channel_binding(ChannelBinding::Require);

    let (client, conn) = pg_config.connect(tls).await.expect("connect");
    tokio::spawn(async move { conn.await.map_err(|e| panic!("{:?}", e)) });

    let stmt = client.prepare("SELECT 1::INT4").await.expect("prepare");
    let rows = client.query(&stmt, &[]).await.expect("query");
    assert_eq!(1, rows.len());
    let res: i32 = (&rows[0]).get(0);
    assert_eq!(1, res);

    let _ = pg.cleanup().await;
}

#[tokio::test]
async fn scram_test_sha512_ok() {
    let mut pg = PostgresContainer::new(
        "scram-sha512",
        "./tests/support/sql_setup.sh",
        "./tests/support/ca.crt",
        "./tests/support/server_sha512.crt",
        "./tests/support/server.key",
    )
    .await
    .expect("start postgres test container");

    let certs = CertStore::sha512();
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(certs.roots)
        .with_client_auth_cert(certs.client_certs, certs.client_key)
        .expect("build rustls client config");
    let tls = MakeRustlsConnect::new(config);

    let mut pg_config = Config::new();
    pg_config
        .host("localhost")
        .port(pg.port)
        .dbname("postgres")
        .user("scram_user")
        .password("password")
        .ssl_mode(SslMode::Require)
        .channel_binding(ChannelBinding::Require);

    let (client, conn) = pg_config.connect(tls).await.expect("connect");
    tokio::spawn(async move { conn.await.map_err(|e| panic!("{:?}", e)) });

    let stmt = client.prepare("SELECT 1::INT4").await.expect("prepare");
    let rows = client.query(&stmt, &[]).await.expect("query");
    assert_eq!(1, rows.len());
    let res: i32 = (&rows[0]).get(0);
    assert_eq!(1, res);

    let _ = pg.cleanup().await;
}
