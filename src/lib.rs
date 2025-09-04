#![doc = include_str!("../README.md")]
#![forbid(rust_2018_idioms)]
#![forbid(missing_docs, unsafe_code)]
#![warn(clippy::all, clippy::pedantic)]

use std::{convert::TryFrom, sync::Arc};

use rustls::{pki_types::ServerName, ClientConfig};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_postgres::tls::MakeTlsConnect;

mod private {
    use std::{
        future::Future,
        io,
        pin::Pin,
        task::{Context, Poll},
    };

    use rustls::pki_types::ServerName;
    use sha2::digest::const_oid::db::{
        rfc5912::{
            ECDSA_WITH_SHA_256, ECDSA_WITH_SHA_384, ID_SHA_1, ID_SHA_256, ID_SHA_384, ID_SHA_512,
            SHA_1_WITH_RSA_ENCRYPTION, SHA_256_WITH_RSA_ENCRYPTION, SHA_384_WITH_RSA_ENCRYPTION,
            SHA_512_WITH_RSA_ENCRYPTION,
        },
        rfc8410::ID_ED_25519,
    };
    use sha2::{Digest, Sha256, Sha384, Sha512};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    use tokio_postgres::tls::{ChannelBinding, TlsConnect};
    use tokio_rustls::{client::TlsStream, TlsConnector};
    use x509_cert::{der::Decode, Certificate};

    pub struct TlsConnectFuture<S> {
        inner: tokio_rustls::Connect<S>,
    }

    impl<S> Future for TlsConnectFuture<S>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        type Output = io::Result<RustlsStream<S>>;

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            Pin::new(&mut self.inner).poll(cx).map_ok(RustlsStream)
        }
    }

    pub struct RustlsConnect(pub RustlsConnectData);

    pub struct RustlsConnectData {
        pub hostname: ServerName<'static>,
        pub connector: TlsConnector,
    }

    impl<S> TlsConnect<S> for RustlsConnect
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        type Stream = RustlsStream<S>;
        type Error = io::Error;
        type Future = TlsConnectFuture<S>;

        fn connect(self, stream: S) -> Self::Future {
            TlsConnectFuture {
                inner: self.0.connector.connect(self.0.hostname, stream),
            }
        }
    }

    pub struct RustlsStream<S>(TlsStream<S>);

    impl<S> tokio_postgres::tls::TlsStream for RustlsStream<S>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        fn channel_binding(&self) -> ChannelBinding {
            let (_, session) = self.0.get_ref();
            match session.peer_certificates() {
                Some(certs) if !certs.is_empty() => Certificate::from_der(&certs[0]).map_or_else(
                    |_| ChannelBinding::none(),
                    |cert| {
                        match cert.signature_algorithm.oid {
                            // Note: SHA1 is upgraded to SHA256 as per https://datatracker.ietf.org/doc/html/rfc5929#section-4.1
                            ID_SHA_1
                            | ID_SHA_256
                            | SHA_1_WITH_RSA_ENCRYPTION
                            | SHA_256_WITH_RSA_ENCRYPTION
                            | ECDSA_WITH_SHA_256 => ChannelBinding::tls_server_end_point(
                                Sha256::digest(certs[0].as_ref()).to_vec(),
                            ),
                            ID_SHA_384 | SHA_384_WITH_RSA_ENCRYPTION | ECDSA_WITH_SHA_384 => {
                                ChannelBinding::tls_server_end_point(
                                    Sha384::digest(certs[0].as_ref()).to_vec(),
                                )
                            }
                            ID_SHA_512 | SHA_512_WITH_RSA_ENCRYPTION | ID_ED_25519 => {
                                ChannelBinding::tls_server_end_point(
                                    Sha512::digest(certs[0].as_ref()).to_vec(),
                                )
                            }
                            _ => ChannelBinding::none(),
                        }
                    },
                ),
                _ => ChannelBinding::none(),
            }
        }
    }

    impl<S> AsyncRead for RustlsStream<S>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<tokio::io::Result<()>> {
            Pin::new(&mut self.0).poll_read(cx, buf)
        }
    }

    impl<S> AsyncWrite for RustlsStream<S>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<tokio::io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, buf)
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<tokio::io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<tokio::io::Result<()>> {
            Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }
}

/// A `MakeTlsConnect` implementation using `rustls`.
///
/// That way you can connect to PostgreSQL using `rustls` as the TLS stack.
#[derive(Clone)]
pub struct MakeRustlsConnect {
    config: Arc<ClientConfig>,
}

impl MakeRustlsConnect {
    /// Creates a new `MakeRustlsConnect` from the provided `ClientConfig`.
    #[must_use]
    pub fn new(config: ClientConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }
}

impl<S> MakeTlsConnect<S> for MakeRustlsConnect
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Stream = private::RustlsStream<S>;
    type TlsConnect = private::RustlsConnect;
    type Error = rustls::pki_types::InvalidDnsNameError;

    fn make_tls_connect(&mut self, hostname: &str) -> Result<Self::TlsConnect, Self::Error> {
        ServerName::try_from(hostname).map(|dns_name| {
            private::RustlsConnect(private::RustlsConnectData {
                hostname: dns_name.to_owned(),
                connector: Arc::clone(&self.config).into(),
            })
        })
    }
}
