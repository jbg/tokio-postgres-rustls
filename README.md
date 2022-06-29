# tokio-postgres-rustls
This is an integration between the [rustls TLS stack](https://github.com/ctz/rustls)
and the [tokio-postgres asynchronous PostgreSQL client library](https://github.com/sfackler/rust-postgres).

[![Crate](https://img.shields.io/crates/v/tokio-postgres-rustls.svg)](https://crates.io/crates/tokio-postgres-rustls)

[API Documentation](https://docs.rs/tokio-postgres-rustls/)

# Example

```
let config = rustls::ClientConfig::builder()
    .with_safe_defaults()
    .with_root_certificates(rustls::RootCertStore::empty())
    .with_no_client_auth();
let tls = tokio_postgres_rustls::MakeRustlsConnect::new(config);
let connect_fut = tokio_postgres::connect("sslmode=require host=localhost user=postgres", tls);
// ...
```

# License
tokio-postgres-rustls is distributed under the MIT license.

# Submitting patches

To submit a patch, please familiarise yourself with [mailing list etiquette](https://man.sr.ht/lists.sr.ht/etiquette.md) and the use of [git-send-email](https://man.sr.ht/git.sr.ht/send-email.md) and then send your patch to the [~jbg/patches mailing list](https://lists.sr.ht/~jbg/patches). Please prefix the subject with [PATCH tokio-postgres-rustls].
