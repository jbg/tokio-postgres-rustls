use bollard::models::{ContainerCreateBody, HostConfig};
use bollard::query_parameters::{
    CreateContainerOptionsBuilder, InspectContainerOptionsBuilder, RemoveContainerOptionsBuilder,
    StartContainerOptionsBuilder, StopContainerOptionsBuilder,
};
use bollard::Docker;
use std::collections::HashMap;
use std::env::current_dir;
use std::error::Error;
use tokio::time::{sleep, timeout, Duration, Instant};
use tokio_postgres::{Config, NoTls};

pub(crate) struct PostgresContainer {
    docker: Docker,
    id: String,
    pub port: u16,
    closed: bool,
}

impl PostgresContainer {
    /// Spin up Postgres 17
    pub(crate) async fn new(
        test_name: &str,
        setup_script: &str,
        ca_cert: &str,
        server_cert: &str,
        server_key: &str,
    ) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let docker = Docker::connect_with_defaults()?;
        let container_name = format!("test-pg-{}", test_name);
        let pwd = current_dir()?
            .to_str()
            .expect("pwd pathref to str")
            .to_owned();

        let binds = vec![
            format!("{pwd}/{setup_script}:/docker-entrypoint-initdb.d/sql_setup.sh:ro"),
            format!("{pwd}/{ca_cert}:/etc/postgresql/certs/ca.crt:ro"),
            format!("{pwd}/{server_cert}:/etc/postgresql/certs/server.crt:ro"),
            format!("{pwd}/{server_key}:/etc/postgresql/certs/server.key:ro"),
        ];

        let mut exposed: HashMap<String, HashMap<(), ()>> = HashMap::new();
        exposed.insert("5433/tcp".into(), HashMap::new());

        let host_config = HostConfig {
            binds: Some(binds),
            publish_all_ports: Some(true),
            ..Default::default()
        };

        let env = vec![
            "POSTGRES_PASSWORD=postgres".to_string(),
            "POSTGRES_USER=postgres".to_string(),
            "POSTGRES_DB=postgres".to_string(),
        ];

        let body = ContainerCreateBody {
            image: Some("postgres:17".to_string()),
            env: Some(env),
            exposed_ports: Some(exposed),
            host_config: Some(host_config),
            ..Default::default()
        };

        let created = docker
            .create_container(
                Some(
                    CreateContainerOptionsBuilder::default()
                        .name(&container_name)
                        .build(),
                ),
                body,
            )
            .await?;
        let id = created.id;

        docker
            .start_container(&id, Some(StartContainerOptionsBuilder::default().build()))
            .await?;

        let inspect = docker
            .inspect_container(&id, Some(InspectContainerOptionsBuilder::default().build()))
            .await?;

        let host_port = inspect
            .network_settings
            .as_ref()
            .and_then(|ns| ns.ports.as_ref())
            .and_then(|ports| ports.get("5433/tcp"))
            .and_then(|opt| opt.as_ref())
            .and_then(|vec| vec.first())
            .and_then(|pb| pb.host_port.as_ref())
            .and_then(|hp| hp.parse::<u16>().ok())
            .ok_or("failed to resolve host port for 5433/tcp")?;

        if !(wait_for_pg(host_port, Duration::from_secs(30))
            .await
            .is_ok())
        {
            cleanup(docker, id).await;
            panic!("postgres container startup probe failed");
        };

        Ok(Self {
            docker,
            id,
            port: host_port,
            closed: false,
        })
    }

    #[must_use = "must cleanup container"]
    pub(crate) async fn cleanup(&mut self) {
        cleanup(self.docker.clone(), self.id.clone()).await;
        // TODO: add error handling and mark `closed` conditional on `Ok`
        self.closed = true;
    }
}

impl Drop for PostgresContainer {
    fn drop(&mut self) {
        // can't run async `cleanup` here, so best we can do is be noisy
        // TODO: log instead of panic?
        assert!(self.closed);
    }
}

async fn cleanup(docker: Docker, id: String) {
    let _ = docker
        .stop_container(
            &id,
            Some(StopContainerOptionsBuilder::default().t(5).build()),
        )
        .await;
    let _ = docker
        .remove_container(
            &id,
            Some(
                RemoveContainerOptionsBuilder::default()
                    .v(true)
                    .force(true)
                    .build(),
            ),
        )
        .await;
}

async fn wait_for_pg(host_port: u16, max_wait: Duration) -> Result<(), &'static str> {
    let mut cfg = Config::new();
    cfg.host("localhost")
        .port(host_port)
        .user("startup_probe")
        .dbname("postgres")
        .ssl_mode(tokio_postgres::config::SslMode::Disable)
        .connect_timeout(Duration::from_secs(2));

    let deadline = Instant::now() + max_wait;

    loop {
        let Ok((client, conn)) = cfg.connect(NoTls).await else {
            if Instant::now() >= deadline {
                return Err("postgres not ready in time");
            }
            sleep(Duration::from_millis(500)).await;
            continue;
        };
        let conn_task = tokio::spawn(async move {
            let _ = conn.await;
        });

        let ok = timeout(Duration::from_secs(2), client.simple_query("SELECT 1"))
            .await
            .ok()
            .and_then(|r| r.ok())
            .is_some();

        conn_task.abort();

        if ok {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("postgres not ready in time");
        }
        sleep(Duration::from_millis(500)).await;
    }
}
