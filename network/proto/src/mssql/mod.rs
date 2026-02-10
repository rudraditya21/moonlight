use std::net::SocketAddr;

use corelib::error::{CoreError, CoreResult};

use crate::ms_tds::{
    AsyncTdsClient, AsyncTdsServer, TdsClient, TdsClientConfig, TdsResponse, TdsServer,
    TdsServerConfig, TdsToken,
};
use crate::util::Timeouts;

pub const MSSQL_DEFAULT_PORT: u16 = crate::ms_tds::MSTDS_DEFAULT_PORT;

#[derive(Debug, Clone)]
pub struct MssqlClientConfig {
    pub timeouts: Timeouts,
    pub username: String,
    pub password: String,
    pub database: String,
}

impl Default for MssqlClientConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
            username: "sa".to_string(),
            password: "moonlight".to_string(),
            database: "master".to_string(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct MssqlQueryResult {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<Option<Vec<u8>>>>,
    pub row_count: u64,
    pub errors: Vec<String>,
}

impl MssqlQueryResult {
    pub fn from_response(resp: &TdsResponse) -> Self {
        let mut out = Self::default();
        for token in &resp.tokens {
            match token {
                TdsToken::ColumnMetadata(cols) => {
                    out.columns = cols.clone();
                }
                TdsToken::Row(values) => {
                    out.rows.push(values.clone());
                }
                TdsToken::Done { row_count } => {
                    out.row_count = *row_count;
                }
                TdsToken::Error(message) => {
                    out.errors.push(message.clone());
                }
            }
        }
        out
    }

    pub fn into_result(self) -> CoreResult<Self> {
        if self.errors.is_empty() {
            Ok(self)
        } else {
            Err(CoreError::Message(self.errors.join("; ")))
        }
    }
}

pub struct MssqlClient {
    inner: TdsClient,
    authenticated: bool,
}

impl MssqlClient {
    pub fn connect(addr: &net::NetAddr, config: MssqlClientConfig) -> CoreResult<Self> {
        let tds_config = TdsClientConfig {
            timeouts: config.timeouts,
            username: config.username,
            password: config.password,
            database: config.database,
        };
        let inner = TdsClient::connect(addr, tds_config)?;
        Ok(Self {
            inner,
            authenticated: true,
        })
    }

    pub fn query(&mut self, sql: &str) -> CoreResult<MssqlQueryResult> {
        if !self.authenticated {
            return Err(CoreError::Message("not authenticated".to_string()));
        }
        let resp = self.inner.query(sql)?;
        MssqlQueryResult::from_response(&resp).into_result()
    }

    pub fn query_raw(&mut self, sql: &str) -> CoreResult<TdsResponse> {
        if !self.authenticated {
            return Err(CoreError::Message("not authenticated".to_string()));
        }
        self.inner.query(sql)
    }
}

pub struct AsyncMssqlClient {
    inner: AsyncTdsClient,
    authenticated: bool,
}

impl AsyncMssqlClient {
    pub async fn connect(addr: &net::NetAddr, config: MssqlClientConfig) -> CoreResult<Self> {
        let tds_config = TdsClientConfig {
            timeouts: config.timeouts,
            username: config.username,
            password: config.password,
            database: config.database,
        };
        let inner = AsyncTdsClient::connect(addr, tds_config).await?;
        Ok(Self {
            inner,
            authenticated: true,
        })
    }

    pub async fn query(&mut self, sql: &str) -> CoreResult<MssqlQueryResult> {
        if !self.authenticated {
            return Err(CoreError::Message("not authenticated".to_string()));
        }
        let resp = self.inner.query(sql).await?;
        MssqlQueryResult::from_response(&resp).into_result()
    }

    pub async fn query_raw(&mut self, sql: &str) -> CoreResult<TdsResponse> {
        if !self.authenticated {
            return Err(CoreError::Message("not authenticated".to_string()));
        }
        self.inner.query(sql).await
    }
}

#[derive(Debug, Clone)]
pub struct MssqlServerConfig {
    pub timeouts: Timeouts,
    pub users: std::collections::HashMap<String, String>,
    pub default_database: String,
}

impl Default for MssqlServerConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
            users: std::collections::HashMap::new(),
            default_database: "master".to_string(),
        }
    }
}

impl From<MssqlServerConfig> for TdsServerConfig {
    fn from(value: MssqlServerConfig) -> Self {
        Self {
            timeouts: value.timeouts,
            users: value.users,
            default_database: value.default_database,
        }
    }
}

pub struct MssqlServer {
    inner: TdsServer,
}

impl MssqlServer {
    pub fn bind(addr: SocketAddr, config: MssqlServerConfig) -> CoreResult<Self> {
        let inner = TdsServer::bind(addr, config.into())?;
        Ok(Self { inner })
    }

    pub fn local_addr(&self) -> CoreResult<SocketAddr> {
        self.inner.local_addr()
    }

    pub fn serve(&self) -> CoreResult<()> {
        self.inner.serve()
    }
}

pub struct AsyncMssqlServer {
    inner: AsyncTdsServer,
}

impl AsyncMssqlServer {
    pub async fn bind(addr: SocketAddr, config: MssqlServerConfig) -> CoreResult<Self> {
        let inner = AsyncTdsServer::bind(addr, config.into()).await?;
        Ok(Self { inner })
    }

    pub async fn serve(&self) -> CoreResult<()> {
        self.inner.serve().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn mssql_query_roundtrip() {
        let mut users = std::collections::HashMap::new();
        users.insert("sa".to_string(), "moonlight".to_string());
        let server = MssqlServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            MssqlServerConfig {
                users,
                ..MssqlServerConfig::default()
            },
        )
        .unwrap();
        let addr = server.local_addr().unwrap();
        thread::spawn(move || {
            let _ = server.serve();
        });

        let mut client = MssqlClient::connect(
            &net::NetAddr::from_socket(addr),
            MssqlClientConfig::default(),
        )
        .unwrap();
        let result = client.query("SELECT 1").unwrap();
        assert_eq!(result.columns.len(), 1);
        assert!(!result.rows.is_empty());
    }
}
