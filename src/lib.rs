#![doc = include_str!("../README.md")]
#![forbid(rust_2018_idioms)]
#![deny(missing_docs, unsafe_code)]
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

    use const_oid::db::{
        rfc5912::{
            ECDSA_WITH_SHA_256, ECDSA_WITH_SHA_384, ID_SHA_1, ID_SHA_256, ID_SHA_384, ID_SHA_512,
            SHA_1_WITH_RSA_ENCRYPTION, SHA_256_WITH_RSA_ENCRYPTION, SHA_384_WITH_RSA_ENCRYPTION,
            SHA_512_WITH_RSA_ENCRYPTION,
        },
        rfc8410::ID_ED_25519,
    };
    use ring::digest;
    use rustls::pki_types::ServerName;
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    use tokio_postgres::tls::{ChannelBinding, TlsConnect};
    use tokio_rustls::{client::TlsStream, TlsConnector};
    use x509_cert::{der::Decode, Certificate};

    pub struct TlsConnectFuture<S> {
        pub inner: tokio_rustls::Connect<S>,
    }

    impl<S> Future for TlsConnectFuture<S>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        type Output = io::Result<RustlsStream<S>>;

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            // SAFETY: If `self` is pinned, so is `inner`.
            #[allow(unsafe_code)]
            let fut = unsafe { self.map_unchecked_mut(|this| &mut this.inner) };
            fut.poll(cx).map_ok(RustlsStream)
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

    impl<S> RustlsStream<S> {
        pub fn project_stream(self: Pin<&mut Self>) -> Pin<&mut TlsStream<S>> {
            // SAFETY: When `Self` is pinned, so is the inner `TlsStream`.
            #[allow(unsafe_code)]
            unsafe {
                self.map_unchecked_mut(|this| &mut this.0)
            }
        }
    }

    impl<S> tokio_postgres::tls::TlsStream for RustlsStream<S>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        fn channel_binding(&self) -> ChannelBinding {
            let (_, session) = self.0.get_ref();
            match session.peer_certificates() {
                Some(certs) if !certs.is_empty() => Certificate::from_der(&certs[0])
                    .ok()
                    .and_then(|cert| {
                        let digest = match cert.signature_algorithm.oid {
                            // Note: SHA1 is upgraded to SHA256 as per https://datatracker.ietf.org/doc/html/rfc5929#section-4.1
                            ID_SHA_1
                            | ID_SHA_256
                            | SHA_1_WITH_RSA_ENCRYPTION
                            | SHA_256_WITH_RSA_ENCRYPTION
                            | ECDSA_WITH_SHA_256 => &digest::SHA256,
                            ID_SHA_384 | SHA_384_WITH_RSA_ENCRYPTION | ECDSA_WITH_SHA_384 => {
                                &digest::SHA384
                            }
                            ID_SHA_512 | SHA_512_WITH_RSA_ENCRYPTION | ID_ED_25519 => {
                                &digest::SHA512
                            }
                            _ => return None,
                        };

                        Some(digest)
                    })
                    .map_or_else(ChannelBinding::none, |algorithm| {
                        let hash = digest::digest(algorithm, certs[0].as_ref());
                        ChannelBinding::tls_server_end_point(hash.as_ref().into())
                    }),
                _ => ChannelBinding::none(),
            }
        }
    }

    impl<S> AsyncRead for RustlsStream<S>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<tokio::io::Result<()>> {
            self.project_stream().poll_read(cx, buf)
        }
    }

    impl<S> AsyncWrite for RustlsStream<S>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<tokio::io::Result<usize>> {
            self.project_stream().poll_write(cx, buf)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<tokio::io::Result<()>> {
            self.project_stream().poll_flush(cx)
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<tokio::io::Result<()>> {
            self.project_stream().poll_shutdown(cx)
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

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::{CertificateDer, UnixTime};
    use rustls::{
        client::danger::ServerCertVerifier,
        client::danger::{HandshakeSignatureValid, ServerCertVerified},
        Error, SignatureScheme,
    };

    #[derive(Debug)]
    struct AcceptAllVerifier {}
    impl ServerCertVerifier for AcceptAllVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::RSA_PSS_SHA512,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::ED25519,
            ]
        }
    }

    #[tokio::test]
    async fn it_works() {
        env_logger::builder().is_test(true).try_init().unwrap();

        let mut config = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(AcceptAllVerifier {}));
        let tls = super::MakeRustlsConnect::new(config);
        let (client, conn) = tokio_postgres::connect(
            "sslmode=require host=localhost port=5432 user=postgres",
            tls,
        )
        .await
        .expect("connect");
        tokio::spawn(async move { conn.await.map_err(|e| panic!("{:?}", e)) });
        let stmt = client.prepare("SELECT 1").await.expect("prepare");
        let _ = client.query(&stmt, &[]).await.expect("query");
    }
}
