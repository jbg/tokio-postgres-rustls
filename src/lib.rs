use std::{future::Future, io, pin::Pin, sync::Arc};

use rustls::ClientConfig;
use tokio_io::{AsyncRead, AsyncWrite};
use tokio_postgres::tls::{ChannelBinding, MakeTlsConnect, TlsConnect};
use tokio_rustls::{client::TlsStream, TlsConnector};
use webpki::{DNSName, DNSNameRef};

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
    type Stream = TlsStream<S>;
    type TlsConnect = RustlsConnect;
    type Error = io::Error;

    fn make_tls_connect(&mut self, hostname: &str) -> Result<RustlsConnect, Self::Error> {
        DNSNameRef::try_from_ascii_str(hostname)
            .map(|dns_name| RustlsConnect {
                hostname: dns_name.to_owned(),
                connector: Arc::clone(&self.config).into(),
            })
            .map_err(|_| io::ErrorKind::InvalidInput.into())
    }
}

pub struct RustlsConnect {
    hostname: DNSName,
    connector: TlsConnector,
}

impl<S> TlsConnect<S> for RustlsConnect
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Stream = TlsStream<S>;
    type Error = io::Error;
    type Future =
        Pin<Box<dyn Future<Output = Result<(Self::Stream, ChannelBinding), Self::Error>> + Send>>;

    fn connect(self, stream: S) -> Self::Future {
        let future = async move {
            let stream: TlsStream<S> = self
                .connector
                .connect(self.hostname.as_ref(), stream)
                .await?;

            Ok((stream, ChannelBinding::none()))
        };

        Box::pin(future)
    }
}

#[cfg(test)]
mod tests {
    use futures_util::future::FutureExt;
    use tokio_postgres::Row;

    #[tokio::test]
    async fn it_works() -> Result<(), tokio_postgres::Error> {
        let config = rustls::ClientConfig::new();
        let tls = super::MakeRustlsConnect::new(config);

        let (client, connection) = tokio_postgres::connect(
            "sslmode=require host=localhost user=postgres",
            tls,
        )
        .await?;

        // spawn connection on tokio
        let connection = connection.map(|r| {
            if let Err(e) = r {
                panic!("connection error: {}", e);
            }
        });
        tokio::spawn(connection);

        let stmt = client.prepare("SELECT $1::TEXT").await?;
        let rows: Vec<Row> = client.query(&stmt, &[&"hello world"]).await?;
        let value: &str = rows[0].get(0);
        assert_eq!(value, "hello world");

        Ok(())
    }
}
