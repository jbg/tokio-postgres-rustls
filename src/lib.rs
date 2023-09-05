use std::{
    convert::TryFrom,
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use DigestAlgorithm::{Sha1, Sha256, Sha384, Sha512};

use futures::future::{FutureExt, TryFutureExt};
use ring::digest;
use rustls::{ClientConfig, ServerName};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_postgres::tls::{ChannelBinding, MakeTlsConnect, TlsConnect};
use tokio_rustls::{client::TlsStream, TlsConnector};
use x509_certificate::{algorithm, DigestAlgorithm, SignatureAlgorithm, X509Certificate};
use SignatureAlgorithm::{
    EcdsaSha256, EcdsaSha384, Ed25519, NoSignature, RsaSha1, RsaSha256, RsaSha384, RsaSha512,
};

#[derive(Clone)]
pub struct MakeRustlsConnect {
    config: Arc<ClientConfig>,
}

impl MakeRustlsConnect {
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
    type Stream = RustlsStream<S>;
    type TlsConnect = RustlsConnect;
    type Error = io::Error;

    fn make_tls_connect(&mut self, hostname: &str) -> io::Result<RustlsConnect> {
        ServerName::try_from(hostname)
            .map(|dns_name| {
                RustlsConnect(Some(RustlsConnectData {
                    hostname: dns_name,
                    connector: Arc::clone(&self.config).into(),
                }))
            })
            .or(Ok(RustlsConnect(None)))
    }
}

pub struct RustlsConnect(Option<RustlsConnectData>);

struct RustlsConnectData {
    hostname: ServerName,
    connector: TlsConnector,
}

impl<S> TlsConnect<S> for RustlsConnect
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Stream = RustlsStream<S>;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = io::Result<RustlsStream<S>>> + Send>>;

    fn connect(self, stream: S) -> Self::Future {
        match self.0 {
            None => Box::pin(core::future::ready(Err(io::ErrorKind::InvalidInput.into()))),
            Some(c) => c
                .connector
                .connect(c.hostname, stream)
                .map_ok(|s| RustlsStream(Box::pin(s)))
                .boxed(),
        }
    }
}

pub struct RustlsStream<S>(Pin<Box<TlsStream<S>>>);

impl<S> tokio_postgres::tls::TlsStream for RustlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn channel_binding(&self) -> ChannelBinding {
        let (_, session) = self.0.get_ref();
        match session.peer_certificates() {
            Some(certs) if !certs.is_empty() => X509Certificate::from_der(&certs[0])
                .ok()
                .and_then(|cert| cert.signature_algorithm())
                .map(|algorithm| match algorithm {
                    // Note: SHA1 is upgraded to SHA256 as per https://datatracker.ietf.org/doc/html/rfc5929#section-4.1
                    RsaSha1 | RsaSha256 | EcdsaSha256 => &digest::SHA256,
                    RsaSha384 | EcdsaSha384 => &digest::SHA384,
                    RsaSha512 => &digest::SHA512,
                    Ed25519 => &digest::SHA512,
                    NoSignature(algo) => match algo {
                        Sha1 | Sha256 => &digest::SHA256,
                        Sha384 => &digest::SHA384,
                        Sha512 => &digest::SHA512,
                    },
                })
                .map(|algorithm| {
                    let hash = digest::digest(algorithm, certs[0].as_ref());
                    ChannelBinding::tls_server_end_point(hash.as_ref().into())
                })
                .unwrap_or(ChannelBinding::none()),
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
        cx: &mut Context,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<tokio::io::Result<()>> {
        self.0.as_mut().poll_read(cx, buf)
    }
}

impl<S> AsyncWrite for RustlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<tokio::io::Result<usize>> {
        self.0.as_mut().poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<tokio::io::Result<()>> {
        self.0.as_mut().poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<tokio::io::Result<()>> {
        self.0.as_mut().poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::future::TryFutureExt;
    use rustls::{client::ServerCertVerified, client::ServerCertVerifier, Certificate, Error};
    use std::time::SystemTime;

    struct AcceptAllVerifier {}
    impl ServerCertVerifier for AcceptAllVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &Certificate,
            _intermediates: &[Certificate],
            _server_name: &ServerName,
            _scts: &mut dyn Iterator<Item = &[u8]>,
            _ocsp_response: &[u8],
            _now: SystemTime,
        ) -> Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }
    }

    #[tokio::test]
    async fn it_works() {
        env_logger::builder().is_test(true).try_init().unwrap();

        let mut config = rustls::ClientConfig::builder()
            .with_safe_defaults()
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
        tokio::spawn(conn.map_err(|e| panic!("{:?}", e)));
        let stmt = client.prepare("SELECT 1").await.expect("prepare");
        let _ = client.query(&stmt, &[]).await.expect("query");
    }
}
