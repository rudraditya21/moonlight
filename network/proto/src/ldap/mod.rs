use std::collections::HashMap;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

use corelib::error::{CoreError, CoreResult};
use ldap3 as ldap3_crate;
use net::NetAddr;

use crate::transport::{AsyncStreamTransport, AsyncTcpTransport, StreamTransport, TcpTransport};
use crate::util::Timeouts;

const TAG_SEQUENCE: u8 = 0x30;
const TAG_SET: u8 = 0x31;
const TAG_INTEGER: u8 = 0x02;
const TAG_ENUM: u8 = 0x0a;
const TAG_BOOLEAN: u8 = 0x01;
const TAG_OCTET_STRING: u8 = 0x04;
#[allow(dead_code)]
const TAG_NULL: u8 = 0x05;
#[allow(dead_code)]
const TAG_OID: u8 = 0x06;

const TAG_BIND_REQUEST: u8 = 0x60;
const TAG_BIND_RESPONSE: u8 = 0x61;
const TAG_UNBIND_REQUEST: u8 = 0x42;
const TAG_SEARCH_REQUEST: u8 = 0x63;
const TAG_SEARCH_ENTRY: u8 = 0x64;
const TAG_SEARCH_DONE: u8 = 0x65;
const TAG_SEARCH_REF: u8 = 0x73;
const TAG_MODIFY_REQUEST: u8 = 0x66;
const TAG_MODIFY_RESPONSE: u8 = 0x67;
const TAG_ADD_REQUEST: u8 = 0x68;
const TAG_ADD_RESPONSE: u8 = 0x69;
const TAG_DEL_REQUEST: u8 = 0x4a;
const TAG_DEL_RESPONSE: u8 = 0x6b;
const TAG_MODDN_REQUEST: u8 = 0x6c;
const TAG_MODDN_RESPONSE: u8 = 0x6d;
const TAG_COMPARE_REQUEST: u8 = 0x6e;
const TAG_COMPARE_RESPONSE: u8 = 0x6f;
const TAG_ABANDON_REQUEST: u8 = 0x50;
const TAG_EXTENDED_REQUEST: u8 = 0x77;
const TAG_EXTENDED_RESPONSE: u8 = 0x78;

const TAG_FILTER_AND: u8 = 0xa0;
const TAG_FILTER_OR: u8 = 0xa1;
const TAG_FILTER_NOT: u8 = 0xa2;
const TAG_FILTER_EQUALITY: u8 = 0xa3;
const TAG_FILTER_SUBSTRINGS: u8 = 0xa4;
const TAG_FILTER_GE: u8 = 0xa5;
const TAG_FILTER_LE: u8 = 0xa6;
const TAG_FILTER_PRESENT: u8 = 0x87;
const TAG_FILTER_APPROX: u8 = 0xa8;
const TAG_FILTER_EXTENSIBLE: u8 = 0xa9;
const MAX_BER_MESSAGE_SIZE: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdapMessage {
    pub message_id: i32,
    pub op: ProtocolOp,
    pub controls: Vec<Control>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolOp {
    BindRequest(BindRequest),
    BindResponse(BindResponse),
    UnbindRequest,
    SearchRequest(SearchRequest),
    SearchResultEntry(SearchResultEntry),
    SearchResultDone(LdapResult),
    SearchResultReference(Vec<String>),
    ModifyRequest(ModifyRequest),
    ModifyResponse(LdapResult),
    AddRequest(AddRequest),
    AddResponse(LdapResult),
    DelRequest(String),
    DelResponse(LdapResult),
    ModifyDnRequest(ModifyDnRequest),
    ModifyDnResponse(LdapResult),
    CompareRequest(CompareRequest),
    CompareResponse(LdapResult),
    AbandonRequest(i32),
    ExtendedRequest(ExtendedRequest),
    ExtendedResponse(ExtendedResponse),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Control {
    pub oid: String,
    pub critical: bool,
    pub value: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindRequest {
    pub version: u8,
    pub name: String,
    pub auth: BindAuth,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindAuth {
    Simple(Vec<u8>),
    Sasl {
        mechanism: String,
        credentials: Option<Vec<u8>>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindResponse {
    pub result: LdapResult,
    pub server_sasl_creds: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchRequest {
    pub base_dn: String,
    pub scope: SearchScope,
    pub deref: DerefAliases,
    pub size_limit: u32,
    pub time_limit: u32,
    pub types_only: bool,
    pub filter: Filter,
    pub attributes: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchScope {
    Base,
    One,
    Subtree,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DerefAliases {
    Never,
    InSearching,
    FindingBase,
    Always,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchResultEntry {
    pub dn: String,
    pub attributes: Vec<Attribute>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModifyRequest {
    pub dn: String,
    pub changes: Vec<Change>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    pub operation: ModifyOp,
    pub modification: Attribute,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModifyOp {
    Add,
    Delete,
    Replace,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddRequest {
    pub dn: String,
    pub attributes: Vec<Attribute>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModifyDnRequest {
    pub dn: String,
    pub new_rdn: String,
    pub delete_old_rdn: bool,
    pub new_superior: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompareRequest {
    pub dn: String,
    pub ava: AttributeValueAssertion,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedRequest {
    pub name: String,
    pub value: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedResponse {
    pub result: LdapResult,
    pub name: Option<String>,
    pub value: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributeValueAssertion {
    pub attribute: String,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribute {
    pub name: String,
    pub values: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Filter {
    And(Vec<Filter>),
    Or(Vec<Filter>),
    Not(Box<Filter>),
    Equality(AttributeValueAssertion),
    Substrings {
        attribute: String,
        substrings: Vec<Substring>,
    },
    GreaterOrEqual(AttributeValueAssertion),
    LessOrEqual(AttributeValueAssertion),
    Present(String),
    Approx(AttributeValueAssertion),
    Extensible(ExtensibleMatch),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Substring {
    Initial(String),
    Any(String),
    Final(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensibleMatch {
    pub matching_rule: Option<String>,
    pub attribute: Option<String>,
    pub value: Vec<u8>,
    pub dn_attributes: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdapResult {
    pub code: ResultCode,
    pub matched_dn: String,
    pub message: String,
    pub referrals: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultCode {
    Success,
    OperationsError,
    ProtocolError,
    TimeLimitExceeded,
    SizeLimitExceeded,
    CompareFalse,
    CompareTrue,
    AuthMethodNotSupported,
    StrongAuthRequired,
    Referral,
    AdminLimitExceeded,
    UnavailableCriticalExtension,
    ConfidentialityRequired,
    SaslBindInProgress,
    NoSuchAttribute,
    UndefinedAttributeType,
    ConstraintViolation,
    AttributeOrValueExists,
    InvalidAttributeSyntax,
    NoSuchObject,
    AliasProblem,
    InvalidDNSyntax,
    AliasDereferencingProblem,
    InappropriateAuthentication,
    InvalidCredentials,
    InsufficientAccess,
    Busy,
    Unavailable,
    UnwillingToPerform,
    LoopDetect,
    NamingViolation,
    ObjectClassViolation,
    NotAllowedOnNonLeaf,
    NotAllowedOnRDN,
    EntryAlreadyExists,
    ObjectClassModsProhibited,
    Other(u32),
}

impl ResultCode {
    fn to_u32(self) -> u32 {
        match self {
            ResultCode::Success => 0,
            ResultCode::OperationsError => 1,
            ResultCode::ProtocolError => 2,
            ResultCode::TimeLimitExceeded => 3,
            ResultCode::SizeLimitExceeded => 4,
            ResultCode::CompareFalse => 5,
            ResultCode::CompareTrue => 6,
            ResultCode::AuthMethodNotSupported => 7,
            ResultCode::StrongAuthRequired => 8,
            ResultCode::Referral => 10,
            ResultCode::AdminLimitExceeded => 11,
            ResultCode::UnavailableCriticalExtension => 12,
            ResultCode::ConfidentialityRequired => 13,
            ResultCode::SaslBindInProgress => 14,
            ResultCode::NoSuchAttribute => 16,
            ResultCode::UndefinedAttributeType => 17,
            ResultCode::ConstraintViolation => 19,
            ResultCode::AttributeOrValueExists => 20,
            ResultCode::InvalidAttributeSyntax => 21,
            ResultCode::NoSuchObject => 32,
            ResultCode::AliasProblem => 33,
            ResultCode::InvalidDNSyntax => 34,
            ResultCode::AliasDereferencingProblem => 36,
            ResultCode::InappropriateAuthentication => 48,
            ResultCode::InvalidCredentials => 49,
            ResultCode::InsufficientAccess => 50,
            ResultCode::Busy => 51,
            ResultCode::Unavailable => 52,
            ResultCode::UnwillingToPerform => 53,
            ResultCode::LoopDetect => 54,
            ResultCode::NamingViolation => 64,
            ResultCode::ObjectClassViolation => 65,
            ResultCode::NotAllowedOnNonLeaf => 66,
            ResultCode::NotAllowedOnRDN => 67,
            ResultCode::EntryAlreadyExists => 68,
            ResultCode::ObjectClassModsProhibited => 69,
            ResultCode::Other(value) => value,
        }
    }

    fn from_u32(value: u32) -> Self {
        match value {
            0 => ResultCode::Success,
            1 => ResultCode::OperationsError,
            2 => ResultCode::ProtocolError,
            3 => ResultCode::TimeLimitExceeded,
            4 => ResultCode::SizeLimitExceeded,
            5 => ResultCode::CompareFalse,
            6 => ResultCode::CompareTrue,
            7 => ResultCode::AuthMethodNotSupported,
            8 => ResultCode::StrongAuthRequired,
            10 => ResultCode::Referral,
            11 => ResultCode::AdminLimitExceeded,
            12 => ResultCode::UnavailableCriticalExtension,
            13 => ResultCode::ConfidentialityRequired,
            14 => ResultCode::SaslBindInProgress,
            16 => ResultCode::NoSuchAttribute,
            17 => ResultCode::UndefinedAttributeType,
            19 => ResultCode::ConstraintViolation,
            20 => ResultCode::AttributeOrValueExists,
            21 => ResultCode::InvalidAttributeSyntax,
            32 => ResultCode::NoSuchObject,
            33 => ResultCode::AliasProblem,
            34 => ResultCode::InvalidDNSyntax,
            36 => ResultCode::AliasDereferencingProblem,
            48 => ResultCode::InappropriateAuthentication,
            49 => ResultCode::InvalidCredentials,
            50 => ResultCode::InsufficientAccess,
            51 => ResultCode::Busy,
            52 => ResultCode::Unavailable,
            53 => ResultCode::UnwillingToPerform,
            54 => ResultCode::LoopDetect,
            64 => ResultCode::NamingViolation,
            65 => ResultCode::ObjectClassViolation,
            66 => ResultCode::NotAllowedOnNonLeaf,
            67 => ResultCode::NotAllowedOnRDN,
            68 => ResultCode::EntryAlreadyExists,
            69 => ResultCode::ObjectClassModsProhibited,
            other => ResultCode::Other(other),
        }
    }
}

impl Default for LdapResult {
    fn default() -> Self {
        Self {
            code: ResultCode::Success,
            matched_dn: String::new(),
            message: String::new(),
            referrals: Vec::new(),
        }
    }
}

pub fn ldap_success() -> LdapResult {
    LdapResult::default()
}

pub struct LdapClient {
    transport: TcpTransport,
    message_id: i32,
}

impl LdapClient {
    pub fn connect(addr: &NetAddr, timeouts: Timeouts) -> CoreResult<Self> {
        let transport = TcpTransport::connect(addr, timeouts)?;
        Ok(Self {
            transport,
            message_id: 1,
        })
    }

    fn next_id(&mut self) -> i32 {
        let id = self.message_id;
        self.message_id = self.message_id.wrapping_add(1);
        id
    }

    pub fn send(&mut self, op: ProtocolOp) -> CoreResult<i32> {
        let message_id = self.next_id();
        let msg = LdapMessage {
            message_id,
            op,
            controls: Vec::new(),
        };
        let bytes = msg.encode()?;
        self.transport.write_all(&bytes)?;
        Ok(message_id)
    }

    pub fn recv(&mut self) -> CoreResult<LdapMessage> {
        let data = read_ber_message(&mut self.transport)?;
        LdapMessage::decode(&data)
    }

    pub fn bind_simple(&mut self, dn: &str, password: &str) -> CoreResult<LdapResult> {
        let req = BindRequest {
            version: 3,
            name: dn.to_string(),
            auth: BindAuth::Simple(password.as_bytes().to_vec()),
        };
        let msg_id = self.send(ProtocolOp::BindRequest(req))?;
        let resp = self.recv()?;
        if resp.message_id != msg_id {
            return Err(CoreError::Message("unexpected message id".to_string()));
        }
        match resp.op {
            ProtocolOp::BindResponse(resp) => Ok(resp.result),
            _ => Err(CoreError::Parse("unexpected response".to_string())),
        }
    }

    pub fn search(
        &mut self,
        request: SearchRequest,
    ) -> CoreResult<(Vec<SearchResultEntry>, LdapResult)> {
        let msg_id = self.send(ProtocolOp::SearchRequest(request))?;
        let mut entries = Vec::new();
        loop {
            let resp = self.recv()?;
            if resp.message_id != msg_id {
                continue;
            }
            match resp.op {
                ProtocolOp::SearchResultEntry(entry) => entries.push(entry),
                ProtocolOp::SearchResultDone(result) => return Ok((entries, result)),
                ProtocolOp::SearchResultReference(_) => {}
                _ => return Err(CoreError::Parse("unexpected response".to_string())),
            }
        }
    }

    pub fn add(&mut self, request: AddRequest) -> CoreResult<LdapResult> {
        let msg_id = self.send(ProtocolOp::AddRequest(request))?;
        let resp = self.recv()?;
        if resp.message_id != msg_id {
            return Err(CoreError::Message("unexpected message id".to_string()));
        }
        match resp.op {
            ProtocolOp::AddResponse(result) => Ok(result),
            _ => Err(CoreError::Parse("unexpected response".to_string())),
        }
    }

    pub fn modify(&mut self, request: ModifyRequest) -> CoreResult<LdapResult> {
        let msg_id = self.send(ProtocolOp::ModifyRequest(request))?;
        let resp = self.recv()?;
        if resp.message_id != msg_id {
            return Err(CoreError::Message("unexpected message id".to_string()));
        }
        match resp.op {
            ProtocolOp::ModifyResponse(result) => Ok(result),
            _ => Err(CoreError::Parse("unexpected response".to_string())),
        }
    }

    pub fn delete(&mut self, dn: &str) -> CoreResult<LdapResult> {
        let msg_id = self.send(ProtocolOp::DelRequest(dn.to_string()))?;
        let resp = self.recv()?;
        if resp.message_id != msg_id {
            return Err(CoreError::Message("unexpected message id".to_string()));
        }
        match resp.op {
            ProtocolOp::DelResponse(result) => Ok(result),
            _ => Err(CoreError::Parse("unexpected response".to_string())),
        }
    }

    pub fn compare(&mut self, request: CompareRequest) -> CoreResult<LdapResult> {
        let msg_id = self.send(ProtocolOp::CompareRequest(request))?;
        let resp = self.recv()?;
        if resp.message_id != msg_id {
            return Err(CoreError::Message("unexpected message id".to_string()));
        }
        match resp.op {
            ProtocolOp::CompareResponse(result) => Ok(result),
            _ => Err(CoreError::Parse("unexpected response".to_string())),
        }
    }

    pub fn unbind(&mut self) -> CoreResult<()> {
        let msg = LdapMessage {
            message_id: self.next_id(),
            op: ProtocolOp::UnbindRequest,
            controls: Vec::new(),
        };
        let bytes = msg.encode()?;
        self.transport.write_all(&bytes)?;
        Ok(())
    }
}

pub struct AsyncLdapClient {
    transport: AsyncTcpTransport,
    message_id: i32,
}

impl AsyncLdapClient {
    pub async fn connect(addr: &NetAddr, timeouts: Timeouts) -> CoreResult<Self> {
        let transport = AsyncTcpTransport::connect(addr, timeouts).await?;
        Ok(Self {
            transport,
            message_id: 1,
        })
    }

    fn next_id(&mut self) -> i32 {
        let id = self.message_id;
        self.message_id = self.message_id.wrapping_add(1);
        id
    }

    pub async fn send(&mut self, op: ProtocolOp) -> CoreResult<i32> {
        let message_id = self.next_id();
        let msg = LdapMessage {
            message_id,
            op,
            controls: Vec::new(),
        };
        let bytes = msg.encode()?;
        self.transport.write_all(&bytes).await?;
        Ok(message_id)
    }

    pub async fn recv(&mut self) -> CoreResult<LdapMessage> {
        let data = read_ber_message_async(&mut self.transport).await?;
        LdapMessage::decode(&data)
    }

    pub async fn bind_simple(&mut self, dn: &str, password: &str) -> CoreResult<LdapResult> {
        let req = BindRequest {
            version: 3,
            name: dn.to_string(),
            auth: BindAuth::Simple(password.as_bytes().to_vec()),
        };
        let msg_id = self.send(ProtocolOp::BindRequest(req)).await?;
        let resp = self.recv().await?;
        if resp.message_id != msg_id {
            return Err(CoreError::Message("unexpected message id".to_string()));
        }
        match resp.op {
            ProtocolOp::BindResponse(resp) => Ok(resp.result),
            _ => Err(CoreError::Parse("unexpected response".to_string())),
        }
    }

    pub async fn search(
        &mut self,
        request: SearchRequest,
    ) -> CoreResult<(Vec<SearchResultEntry>, LdapResult)> {
        let msg_id = self.send(ProtocolOp::SearchRequest(request)).await?;
        let mut entries = Vec::new();
        loop {
            let resp = self.recv().await?;
            if resp.message_id != msg_id {
                continue;
            }
            match resp.op {
                ProtocolOp::SearchResultEntry(entry) => entries.push(entry),
                ProtocolOp::SearchResultDone(result) => return Ok((entries, result)),
                ProtocolOp::SearchResultReference(_) => {}
                _ => return Err(CoreError::Parse("unexpected response".to_string())),
            }
        }
    }

    pub async fn unbind(&mut self) -> CoreResult<()> {
        let msg = LdapMessage {
            message_id: self.next_id(),
            op: ProtocolOp::UnbindRequest,
            controls: Vec::new(),
        };
        let bytes = msg.encode()?;
        self.transport.write_all(&bytes).await?;
        Ok(())
    }
}

pub struct UpstreamLdapClient {
    runtime: tokio::runtime::Runtime,
    inner: AsyncUpstreamLdapClient,
}

impl UpstreamLdapClient {
    pub fn connect(addr: &NetAddr, _timeouts: Timeouts) -> CoreResult<Self> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|err| CoreError::Message(err.to_string()))?;
        let inner = runtime.block_on(AsyncUpstreamLdapClient::connect(addr))?;
        Ok(Self { runtime, inner })
    }

    pub fn bind_simple(&mut self, dn: &str, password: &str) -> CoreResult<LdapResult> {
        self.runtime.block_on(self.inner.bind_simple(dn, password))
    }

    pub fn search(
        &mut self,
        request: SearchRequest,
    ) -> CoreResult<(Vec<SearchResultEntry>, LdapResult)> {
        self.runtime.block_on(self.inner.search(request))
    }

    pub fn unbind(&mut self) -> CoreResult<()> {
        self.runtime.block_on(self.inner.unbind())
    }
}

pub struct AsyncUpstreamLdapClient {
    ldap: ldap3_crate::Ldap,
}

impl AsyncUpstreamLdapClient {
    pub async fn connect(addr: &NetAddr) -> CoreResult<Self> {
        let socket = addr
            .resolve()?
            .into_iter()
            .next()
            .ok_or_else(|| CoreError::Parse("unable to resolve".to_string()))?;
        let url = format!("ldap://{}:{}", socket.ip(), socket.port());
        let (conn, ldap) = ldap3_crate::LdapConnAsync::new(&url)
            .await
            .map_err(|err| CoreError::Message(format!("ldap connect failed: {err}")))?;
        tokio::spawn(async move {
            let _ = conn.drive().await;
        });
        Ok(Self { ldap })
    }

    pub async fn bind_simple(&mut self, dn: &str, password: &str) -> CoreResult<LdapResult> {
        let result = self
            .ldap
            .simple_bind(dn, password)
            .await
            .map_err(|err| CoreError::Message(format!("ldap bind failed: {err}")))?
            .success()
            .map_err(|err| CoreError::Message(format!("ldap bind failed: {err}")))?;
        Ok(map_ldap3_result(&result))
    }

    pub async fn search(
        &mut self,
        request: SearchRequest,
    ) -> CoreResult<(Vec<SearchResultEntry>, LdapResult)> {
        let scope = match request.scope {
            SearchScope::Base => ldap3_crate::Scope::Base,
            SearchScope::One => ldap3_crate::Scope::OneLevel,
            SearchScope::Subtree => ldap3_crate::Scope::Subtree,
        };
        let attrs = request.attributes.clone();
        let filter = ldap_filter_to_string(&request.filter);
        let (entries, result) = self
            .ldap
            .search(&request.base_dn, scope, &filter, attrs)
            .await
            .map_err(|err| CoreError::Message(format!("ldap search failed: {err}")))?
            .success()
            .map_err(|err| CoreError::Message(format!("ldap search failed: {err}")))?;

        let mut out = Vec::with_capacity(entries.len());
        for entry in entries {
            let entry = ldap3_crate::SearchEntry::construct(entry);
            let mut attributes = Vec::new();
            for (name, values) in entry.attrs {
                attributes.push(Attribute {
                    name,
                    values: values.into_iter().map(|v| v.into_bytes()).collect(),
                });
            }
            for (name, values) in entry.bin_attrs {
                attributes.push(Attribute { name, values });
            }
            out.push(SearchResultEntry {
                dn: entry.dn,
                attributes,
            });
        }
        Ok((out, map_ldap3_result(&result)))
    }

    pub async fn unbind(&mut self) -> CoreResult<()> {
        self.ldap
            .unbind()
            .await
            .map_err(|err| CoreError::Message(format!("ldap unbind failed: {err}")))
    }
}

fn map_ldap3_result(result: &ldap3_crate::LdapResult) -> LdapResult {
    LdapResult {
        code: map_ldap3_code(result.rc),
        matched_dn: result.matched.clone(),
        message: result.text.clone(),
        referrals: result.refs.clone(),
    }
}

fn map_ldap3_code(rc: u32) -> ResultCode {
    ResultCode::from_u32(rc)
}

fn ldap_filter_to_string(filter: &Filter) -> String {
    match filter {
        Filter::And(filters) => {
            let mut out = String::from("(&");
            for item in filters {
                out.push_str(&ldap_filter_to_string(item));
            }
            out.push(')');
            out
        }
        Filter::Or(filters) => {
            let mut out = String::from("(|");
            for item in filters {
                out.push_str(&ldap_filter_to_string(item));
            }
            out.push(')');
            out
        }
        Filter::Not(item) => format!("(!{})", ldap_filter_to_string(item)),
        Filter::Equality(ava) => format!(
            "({}={})",
            ava.attribute,
            ldap_escape_filter_value(&ava.value)
        ),
        Filter::Substrings {
            attribute,
            substrings,
        } => {
            let mut out = format!("({attribute}=");
            for part in substrings {
                match part {
                    Substring::Initial(v) | Substring::Any(v) | Substring::Final(v) => {
                        out.push_str(&ldap_escape_filter_str(v));
                        out.push('*');
                    }
                }
            }
            out.push(')');
            out
        }
        Filter::GreaterOrEqual(ava) => format!(
            "({}>={})",
            ava.attribute,
            ldap_escape_filter_value(&ava.value)
        ),
        Filter::LessOrEqual(ava) => format!(
            "({}<={})",
            ava.attribute,
            ldap_escape_filter_value(&ava.value)
        ),
        Filter::Present(attribute) => format!("({}=*)", attribute),
        Filter::Approx(ava) => format!(
            "({}~={})",
            ava.attribute,
            ldap_escape_filter_value(&ava.value)
        ),
        Filter::Extensible(ext) => {
            let attr = ext.attribute.clone().unwrap_or_default();
            let rule = ext.matching_rule.clone().unwrap_or_default();
            let dn_flag = if ext.dn_attributes { ":dn" } else { "" };
            format!(
                "({attr}:{dn_flag}:{rule}:={})",
                ldap_escape_filter_value(&ext.value)
            )
        }
    }
}

fn ldap_escape_filter_str(value: &str) -> String {
    ldap_escape_filter_value(value.as_bytes())
}

fn ldap_escape_filter_value(value: &[u8]) -> String {
    let mut out = String::new();
    for &b in value {
        match b {
            b'(' | b')' | b'*' | b'\\' | 0x00 => out.push_str(&format!("\\{:02x}", b)),
            _ => out.push(b as char),
        }
    }
    out
}

pub trait LdapBackend: Send + Sync {
    fn bind(&self, req: &BindRequest) -> CoreResult<LdapResult>;
    fn search(&self, req: &SearchRequest) -> CoreResult<Vec<SearchResultEntry>>;
    fn add(&self, req: &AddRequest) -> CoreResult<LdapResult>;
    fn modify(&self, req: &ModifyRequest) -> CoreResult<LdapResult>;
    fn delete(&self, dn: &str) -> CoreResult<LdapResult>;
    fn compare(&self, req: &CompareRequest) -> CoreResult<LdapResult>;
    fn extended(&self, req: &ExtendedRequest) -> CoreResult<ExtendedResponse>;
}

#[derive(Debug, Clone)]
pub struct InMemoryBackend {
    entries: Arc<Mutex<HashMap<String, SearchResultEntry>>>,
    allow_anonymous: bool,
}

impl InMemoryBackend {
    pub fn new() -> Self {
        Self {
            entries: Arc::new(Mutex::new(HashMap::new())),
            allow_anonymous: true,
        }
    }

    pub fn with_entry(self, entry: SearchResultEntry) -> Self {
        let mut guard = self.entries.lock().expect("entries");
        guard.insert(normalize_dn(&entry.dn), entry);
        drop(guard);
        self
    }

    pub fn allow_anonymous(mut self, allow: bool) -> Self {
        self.allow_anonymous = allow;
        self
    }
}

impl Default for InMemoryBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl LdapBackend for InMemoryBackend {
    fn bind(&self, req: &BindRequest) -> CoreResult<LdapResult> {
        match &req.auth {
            BindAuth::Simple(secret) => {
                if req.name.is_empty() {
                    return Ok(ldap_success());
                }
                let dn = normalize_dn(&req.name);
                let guard = self
                    .entries
                    .lock()
                    .map_err(|_| CoreError::Message("entries poisoned".to_string()))?;
                let entry = guard
                    .get(&dn)
                    .ok_or_else(|| CoreError::Message("no such object".to_string()))?;
                let mut password_ok = false;
                for attr in &entry.attributes {
                    if attr.name.eq_ignore_ascii_case("userpassword") {
                        for value in &attr.values {
                            if value == secret {
                                password_ok = true;
                                break;
                            }
                        }
                    }
                }
                if password_ok {
                    Ok(ldap_success())
                } else {
                    Ok(LdapResult {
                        code: ResultCode::InvalidCredentials,
                        matched_dn: req.name.clone(),
                        message: "invalid credentials".to_string(),
                        referrals: Vec::new(),
                    })
                }
            }
            BindAuth::Sasl { .. } => Ok(LdapResult {
                code: ResultCode::AuthMethodNotSupported,
                matched_dn: req.name.clone(),
                message: "sasl not supported".to_string(),
                referrals: Vec::new(),
            }),
        }
    }

    fn search(&self, req: &SearchRequest) -> CoreResult<Vec<SearchResultEntry>> {
        let guard = self
            .entries
            .lock()
            .map_err(|_| CoreError::Message("entries poisoned".to_string()))?;
        let mut results = Vec::new();
        let base = normalize_dn(&req.base_dn);
        for entry in guard.values() {
            if !match_scope(&base, &normalize_dn(&entry.dn), req.scope) {
                continue;
            }
            if !filter_match(&req.filter, entry) {
                continue;
            }
            let mut out_entry = entry.clone();
            if req.types_only {
                for attr in &mut out_entry.attributes {
                    attr.values.clear();
                }
            } else if !req.attributes.is_empty() {
                out_entry.attributes = filter_attributes(&out_entry.attributes, &req.attributes);
            }
            results.push(out_entry);
        }
        Ok(results)
    }

    fn add(&self, req: &AddRequest) -> CoreResult<LdapResult> {
        let mut guard = self
            .entries
            .lock()
            .map_err(|_| CoreError::Message("entries poisoned".to_string()))?;
        let dn = normalize_dn(&req.dn);
        if guard.contains_key(&dn) {
            return Ok(LdapResult {
                code: ResultCode::EntryAlreadyExists,
                matched_dn: req.dn.clone(),
                message: "entry exists".to_string(),
                referrals: Vec::new(),
            });
        }
        let entry = SearchResultEntry {
            dn: req.dn.clone(),
            attributes: req.attributes.clone(),
        };
        guard.insert(dn, entry);
        Ok(ldap_success())
    }

    fn modify(&self, req: &ModifyRequest) -> CoreResult<LdapResult> {
        let mut guard = self
            .entries
            .lock()
            .map_err(|_| CoreError::Message("entries poisoned".to_string()))?;
        let dn = normalize_dn(&req.dn);
        let entry = guard
            .get_mut(&dn)
            .ok_or_else(|| CoreError::Message("no such object".to_string()))?;
        for change in &req.changes {
            apply_change(entry, change)?;
        }
        Ok(ldap_success())
    }

    fn delete(&self, dn: &str) -> CoreResult<LdapResult> {
        let mut guard = self
            .entries
            .lock()
            .map_err(|_| CoreError::Message("entries poisoned".to_string()))?;
        let key = normalize_dn(dn);
        if guard.remove(&key).is_some() {
            Ok(ldap_success())
        } else {
            Ok(LdapResult {
                code: ResultCode::NoSuchObject,
                matched_dn: dn.to_string(),
                message: "no such object".to_string(),
                referrals: Vec::new(),
            })
        }
    }

    fn compare(&self, req: &CompareRequest) -> CoreResult<LdapResult> {
        let guard = self
            .entries
            .lock()
            .map_err(|_| CoreError::Message("entries poisoned".to_string()))?;
        let dn = normalize_dn(&req.dn);
        let entry = guard
            .get(&dn)
            .ok_or_else(|| CoreError::Message("no such object".to_string()))?;
        let mut matched = false;
        for attr in &entry.attributes {
            if attr.name.eq_ignore_ascii_case(&req.ava.attribute) {
                for value in &attr.values {
                    if values_equal(value, &req.ava.value) {
                        matched = true;
                        break;
                    }
                }
            }
            if matched {
                break;
            }
        }
        Ok(LdapResult {
            code: if matched {
                ResultCode::CompareTrue
            } else {
                ResultCode::CompareFalse
            },
            matched_dn: req.dn.clone(),
            message: String::new(),
            referrals: Vec::new(),
        })
    }

    fn extended(&self, req: &ExtendedRequest) -> CoreResult<ExtendedResponse> {
        Ok(ExtendedResponse {
            result: LdapResult {
                code: ResultCode::UnavailableCriticalExtension,
                matched_dn: String::new(),
                message: format!("unsupported extended request {}", req.name),
                referrals: Vec::new(),
            },
            name: None,
            value: None,
        })
    }
}

pub struct LdapServer {
    listener: TcpListener,
    backend: Arc<dyn LdapBackend>,
    timeouts: Timeouts,
}

impl LdapServer {
    pub fn bind(
        addr: SocketAddr,
        timeouts: Timeouts,
        backend: Arc<dyn LdapBackend>,
    ) -> CoreResult<Self> {
        let listener = TcpListener::bind(addr).map_err(CoreError::Io)?;
        Ok(Self {
            listener,
            backend,
            timeouts,
        })
    }

    pub fn local_addr(&self) -> CoreResult<SocketAddr> {
        self.listener.local_addr().map_err(CoreError::Io)
    }

    pub fn serve(&self) -> CoreResult<()> {
        for stream in self.listener.incoming() {
            let stream = stream.map_err(CoreError::Io)?;
            let backend = Arc::clone(&self.backend);
            let timeouts = self.timeouts;
            thread::spawn(move || {
                let _ = handle_session(stream, timeouts, backend);
            });
        }
        Ok(())
    }
}

pub struct AsyncLdapServer {
    listener: tokio::net::TcpListener,
    backend: Arc<dyn LdapBackend>,
    timeouts: Timeouts,
}

impl AsyncLdapServer {
    pub async fn bind(
        addr: SocketAddr,
        timeouts: Timeouts,
        backend: Arc<dyn LdapBackend>,
    ) -> CoreResult<Self> {
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(CoreError::Io)?;
        Ok(Self {
            listener,
            backend,
            timeouts,
        })
    }

    pub fn local_addr(&self) -> CoreResult<SocketAddr> {
        self.listener.local_addr().map_err(CoreError::Io)
    }

    pub async fn serve(&self) -> CoreResult<()> {
        loop {
            let (stream, _) = self.listener.accept().await.map_err(CoreError::Io)?;
            let backend = Arc::clone(&self.backend);
            let timeouts = self.timeouts;
            tokio::spawn(async move {
                let _ = handle_session_async(stream, timeouts, backend).await;
            });
        }
    }
}

fn handle_session(
    stream: TcpStream,
    timeouts: Timeouts,
    backend: Arc<dyn LdapBackend>,
) -> CoreResult<()> {
    let mut transport = TcpTransport::from_stream(stream, timeouts)?;
    loop {
        let data = match read_ber_message(&mut transport) {
            Ok(data) => data,
            Err(CoreError::Io(err)) if err.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Ok(())
            }
            Err(CoreError::Io(err)) if err.kind() == std::io::ErrorKind::ConnectionReset => {
                return Ok(())
            }
            Err(err) => return Err(err),
        };
        let message = LdapMessage::decode(&data)?;
        let responses = handle_message(&backend, message)?;
        for resp in responses {
            let bytes = resp.encode()?;
            transport.write_all(&bytes)?;
        }
    }
}

async fn handle_session_async(
    stream: tokio::net::TcpStream,
    _timeouts: Timeouts,
    backend: Arc<dyn LdapBackend>,
) -> CoreResult<()> {
    let mut transport = AsyncTcpTransport::from_stream(stream);
    loop {
        let data = match read_ber_message_async(&mut transport).await {
            Ok(data) => data,
            Err(CoreError::Io(err)) if err.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Ok(())
            }
            Err(CoreError::Io(err)) if err.kind() == std::io::ErrorKind::ConnectionReset => {
                return Ok(())
            }
            Err(err) => return Err(err),
        };
        let message = LdapMessage::decode(&data)?;
        let responses = handle_message(&backend, message)?;
        for resp in responses {
            let bytes = resp.encode()?;
            transport.write_all(&bytes).await?;
        }
    }
}

fn handle_message(
    backend: &Arc<dyn LdapBackend>,
    message: LdapMessage,
) -> CoreResult<Vec<LdapMessage>> {
    let msg_id = message.message_id;
    match message.op {
        ProtocolOp::BindRequest(req) => {
            let result = backend.bind(&req)?;
            let resp = BindResponse {
                result,
                server_sasl_creds: None,
            };
            Ok(vec![LdapMessage {
                message_id: msg_id,
                op: ProtocolOp::BindResponse(resp),
                controls: Vec::new(),
            }])
        }
        ProtocolOp::SearchRequest(req) => {
            let entries = backend.search(&req)?;
            let mut messages = Vec::new();
            for entry in entries {
                messages.push(LdapMessage {
                    message_id: msg_id,
                    op: ProtocolOp::SearchResultEntry(entry),
                    controls: Vec::new(),
                });
            }
            messages.push(LdapMessage {
                message_id: msg_id,
                op: ProtocolOp::SearchResultDone(ldap_success()),
                controls: Vec::new(),
            });
            Ok(messages)
        }
        ProtocolOp::AddRequest(req) => {
            let result = backend.add(&req)?;
            Ok(vec![LdapMessage {
                message_id: msg_id,
                op: ProtocolOp::AddResponse(result),
                controls: Vec::new(),
            }])
        }
        ProtocolOp::ModifyRequest(req) => {
            let result = backend.modify(&req)?;
            Ok(vec![LdapMessage {
                message_id: msg_id,
                op: ProtocolOp::ModifyResponse(result),
                controls: Vec::new(),
            }])
        }
        ProtocolOp::DelRequest(dn) => {
            let result = backend.delete(&dn)?;
            Ok(vec![LdapMessage {
                message_id: msg_id,
                op: ProtocolOp::DelResponse(result),
                controls: Vec::new(),
            }])
        }
        ProtocolOp::ModifyDnRequest(req) => {
            let mut result = backend.delete(&req.dn)?;
            if result.code == ResultCode::Success {
                let new_dn = if let Some(superior) = req.new_superior.clone() {
                    format!("{},{}", req.new_rdn, superior)
                } else {
                    req.new_rdn.clone()
                };
                let entry = SearchResultEntry {
                    dn: new_dn.clone(),
                    attributes: Vec::new(),
                };
                result = backend.add(&AddRequest {
                    dn: new_dn,
                    attributes: entry.attributes,
                })?;
            }
            Ok(vec![LdapMessage {
                message_id: msg_id,
                op: ProtocolOp::ModifyDnResponse(result),
                controls: Vec::new(),
            }])
        }
        ProtocolOp::CompareRequest(req) => {
            let result = backend.compare(&req)?;
            Ok(vec![LdapMessage {
                message_id: msg_id,
                op: ProtocolOp::CompareResponse(result),
                controls: Vec::new(),
            }])
        }
        ProtocolOp::ExtendedRequest(req) => {
            let resp = backend.extended(&req)?;
            Ok(vec![LdapMessage {
                message_id: msg_id,
                op: ProtocolOp::ExtendedResponse(resp),
                controls: Vec::new(),
            }])
        }
        ProtocolOp::UnbindRequest => Ok(Vec::new()),
        ProtocolOp::AbandonRequest(_) => Ok(Vec::new()),
        _ => Ok(vec![LdapMessage {
            message_id: msg_id,
            op: ProtocolOp::BindResponse(BindResponse {
                result: LdapResult {
                    code: ResultCode::ProtocolError,
                    matched_dn: String::new(),
                    message: "unsupported request".to_string(),
                    referrals: Vec::new(),
                },
                server_sasl_creds: None,
            }),
            controls: Vec::new(),
        }]),
    }
}

impl LdapMessage {
    pub fn encode(&self) -> CoreResult<Vec<u8>> {
        let mut elements = Vec::new();
        elements.push(encode_integer(self.message_id as i64));
        elements.push(encode_protocol_op(&self.op)?);
        if !self.controls.is_empty() {
            elements.push(encode_controls(&self.controls));
        }
        Ok(encode_sequence(&elements))
    }

    pub fn decode(data: &[u8]) -> CoreResult<Self> {
        let element = BerElement::decode(data)?;
        if element.tag != TAG_SEQUENCE {
            return Err(CoreError::Parse("invalid ldap message".to_string()));
        }
        let mut reader = BerReader::new(&element.content);
        let msg_id = reader.read_integer()?;
        if !(0..=i32::MAX as i64).contains(&msg_id) {
            return Err(CoreError::Parse("ldap message id out of range".to_string()));
        }
        let op_element = reader.read_element()?;
        let op = decode_protocol_op(op_element)?;
        let controls = if reader.remaining() > 0 {
            let control_element = reader.read_element()?;
            decode_controls(&control_element)?
        } else {
            Vec::new()
        };
        Ok(Self {
            message_id: msg_id as i32,
            op,
            controls,
        })
    }
}

fn encode_protocol_op(op: &ProtocolOp) -> CoreResult<Vec<u8>> {
    match op {
        ProtocolOp::BindRequest(req) => Ok(encode_bind_request(req)),
        ProtocolOp::BindResponse(resp) => Ok(encode_bind_response(resp)),
        ProtocolOp::UnbindRequest => Ok(encode_tagged(TAG_UNBIND_REQUEST, Vec::new())),
        ProtocolOp::SearchRequest(req) => Ok(encode_search_request(req)?),
        ProtocolOp::SearchResultEntry(entry) => Ok(encode_search_entry(entry)),
        ProtocolOp::SearchResultDone(result) => Ok(encode_search_done(result)),
        ProtocolOp::SearchResultReference(uris) => Ok(encode_search_ref(uris)),
        ProtocolOp::ModifyRequest(req) => Ok(encode_modify_request(req)?),
        ProtocolOp::ModifyResponse(result) => Ok(encode_tagged(
            TAG_MODIFY_RESPONSE,
            encode_ldap_result(result),
        )),
        ProtocolOp::AddRequest(req) => Ok(encode_add_request(req)?),
        ProtocolOp::AddResponse(result) => {
            Ok(encode_tagged(TAG_ADD_RESPONSE, encode_ldap_result(result)))
        }
        ProtocolOp::DelRequest(dn) => Ok(encode_tagged(TAG_DEL_REQUEST, dn.as_bytes().to_vec())),
        ProtocolOp::DelResponse(result) => {
            Ok(encode_tagged(TAG_DEL_RESPONSE, encode_ldap_result(result)))
        }
        ProtocolOp::ModifyDnRequest(req) => Ok(encode_moddn_request(req)?),
        ProtocolOp::ModifyDnResponse(result) => Ok(encode_tagged(
            TAG_MODDN_RESPONSE,
            encode_ldap_result(result),
        )),
        ProtocolOp::CompareRequest(req) => Ok(encode_compare_request(req)?),
        ProtocolOp::CompareResponse(result) => Ok(encode_tagged(
            TAG_COMPARE_RESPONSE,
            encode_ldap_result(result),
        )),
        ProtocolOp::AbandonRequest(msg_id) => Ok(encode_tagged(
            TAG_ABANDON_REQUEST,
            encode_integer_content(*msg_id as i64),
        )),
        ProtocolOp::ExtendedRequest(req) => Ok(encode_extended_request(req)?),
        ProtocolOp::ExtendedResponse(resp) => Ok(encode_extended_response(resp)?),
    }
}

fn decode_protocol_op(element: BerElement) -> CoreResult<ProtocolOp> {
    match element.tag {
        TAG_BIND_REQUEST => Ok(ProtocolOp::BindRequest(decode_bind_request(&element)?)),
        TAG_BIND_RESPONSE => Ok(ProtocolOp::BindResponse(decode_bind_response(&element)?)),
        TAG_UNBIND_REQUEST => Ok(ProtocolOp::UnbindRequest),
        TAG_SEARCH_REQUEST => Ok(ProtocolOp::SearchRequest(decode_search_request(&element)?)),
        TAG_SEARCH_ENTRY => Ok(ProtocolOp::SearchResultEntry(decode_search_entry(
            &element,
        )?)),
        TAG_SEARCH_DONE => Ok(ProtocolOp::SearchResultDone(decode_ldap_result(&element)?)),
        TAG_SEARCH_REF => Ok(ProtocolOp::SearchResultReference(decode_search_ref(
            &element,
        )?)),
        TAG_MODIFY_REQUEST => Ok(ProtocolOp::ModifyRequest(decode_modify_request(&element)?)),
        TAG_MODIFY_RESPONSE => Ok(ProtocolOp::ModifyResponse(decode_ldap_result(&element)?)),
        TAG_ADD_REQUEST => Ok(ProtocolOp::AddRequest(decode_add_request(&element)?)),
        TAG_ADD_RESPONSE => Ok(ProtocolOp::AddResponse(decode_ldap_result(&element)?)),
        TAG_DEL_REQUEST => Ok(ProtocolOp::DelRequest(
            String::from_utf8_lossy(&element.content).to_string(),
        )),
        TAG_DEL_RESPONSE => Ok(ProtocolOp::DelResponse(decode_ldap_result(&element)?)),
        TAG_MODDN_REQUEST => Ok(ProtocolOp::ModifyDnRequest(decode_moddn_request(&element)?)),
        TAG_MODDN_RESPONSE => Ok(ProtocolOp::ModifyDnResponse(decode_ldap_result(&element)?)),
        TAG_COMPARE_REQUEST => Ok(ProtocolOp::CompareRequest(decode_compare_request(
            &element,
        )?)),
        TAG_COMPARE_RESPONSE => Ok(ProtocolOp::CompareResponse(decode_ldap_result(&element)?)),
        TAG_ABANDON_REQUEST => {
            let msg_id = decode_integer_content(&element.content)? as i32;
            Ok(ProtocolOp::AbandonRequest(msg_id))
        }
        TAG_EXTENDED_REQUEST => Ok(ProtocolOp::ExtendedRequest(decode_extended_request(
            &element,
        )?)),
        TAG_EXTENDED_RESPONSE => Ok(ProtocolOp::ExtendedResponse(decode_extended_response(
            &element,
        )?)),
        _ => Err(CoreError::Parse("unknown protocol op".to_string())),
    }
}

fn encode_bind_request(req: &BindRequest) -> Vec<u8> {
    let mut elements = Vec::new();
    elements.push(encode_integer(req.version as i64));
    elements.push(encode_octet_string(req.name.as_bytes()));
    match &req.auth {
        BindAuth::Simple(secret) => {
            elements.push(encode_tagged(0x80, secret.clone()));
        }
        BindAuth::Sasl {
            mechanism,
            credentials,
        } => {
            let mut sasl = Vec::new();
            sasl.push(encode_octet_string(mechanism.as_bytes()));
            if let Some(creds) = credentials {
                sasl.push(encode_octet_string(creds));
            }
            let seq = encode_sequence(&sasl);
            elements.push(encode_tagged(0xa3, seq));
        }
    }
    encode_constructed(TAG_BIND_REQUEST, &elements)
}

fn decode_bind_request(element: &BerElement) -> CoreResult<BindRequest> {
    let mut reader = BerReader::new(&element.content);
    let version = reader.read_integer()? as u8;
    let name = reader.read_octet_string()?;
    let auth_elem = reader.read_element()?;
    let auth = match auth_elem.tag {
        0x80 => BindAuth::Simple(auth_elem.content.clone()),
        0xa3 => {
            let mut sasl_reader = BerReader::new(&auth_elem.content);
            let mech = sasl_reader.read_octet_string()?;
            let creds = if sasl_reader.remaining() > 0 {
                Some(sasl_reader.read_octet_string_bytes()?)
            } else {
                None
            };
            BindAuth::Sasl {
                mechanism: mech,
                credentials: creds,
            }
        }
        _ => return Err(CoreError::Parse("invalid bind auth".to_string())),
    };
    Ok(BindRequest {
        version,
        name,
        auth,
    })
}

fn encode_bind_response(resp: &BindResponse) -> Vec<u8> {
    let mut result = encode_ldap_result(&resp.result);
    if let Some(creds) = &resp.server_sasl_creds {
        let tagged = encode_tagged(0x87, creds.clone());
        result.extend_from_slice(&tagged);
    }
    encode_tagged(TAG_BIND_RESPONSE, result)
}

fn decode_bind_response(element: &BerElement) -> CoreResult<BindResponse> {
    let mut reader = BerReader::new(&element.content);
    let result = decode_ldap_result_from_reader(&mut reader)?;
    let server_sasl_creds = if reader.remaining() > 0 {
        let elem = reader.read_element()?;
        if elem.tag == 0x87 {
            Some(elem.content)
        } else {
            None
        }
    } else {
        None
    };
    Ok(BindResponse {
        result,
        server_sasl_creds,
    })
}

fn encode_search_request(req: &SearchRequest) -> CoreResult<Vec<u8>> {
    let mut elements = Vec::new();
    elements.push(encode_octet_string(req.base_dn.as_bytes()));
    elements.push(encode_enum(req.scope.to_u32()));
    elements.push(encode_enum(req.deref.to_u32()));
    elements.push(encode_integer(req.size_limit as i64));
    elements.push(encode_integer(req.time_limit as i64));
    elements.push(encode_boolean(req.types_only));
    elements.push(encode_filter(&req.filter)?);
    let mut attrs = Vec::new();
    for attr in &req.attributes {
        attrs.push(encode_octet_string(attr.as_bytes()));
    }
    elements.push(encode_sequence(&attrs));
    Ok(encode_constructed(TAG_SEARCH_REQUEST, &elements))
}

fn decode_search_request(element: &BerElement) -> CoreResult<SearchRequest> {
    let mut reader = BerReader::new(&element.content);
    let base_dn = reader.read_octet_string()?;
    let scope = SearchScope::from_u32(reader.read_enum()? as u32)?;
    let deref = DerefAliases::from_u32(reader.read_enum()? as u32)?;
    let size_limit = reader.read_integer()? as u32;
    let time_limit = reader.read_integer()? as u32;
    let types_only = reader.read_boolean()?;
    let filter_elem = reader.read_element()?;
    let filter = decode_filter(filter_elem)?;
    let attrs_elem = reader.read_element()?;
    let mut attrs_reader = BerReader::new(&attrs_elem.content);
    let mut attrs = Vec::new();
    while attrs_reader.remaining() > 0 {
        attrs.push(attrs_reader.read_octet_string()?);
    }
    Ok(SearchRequest {
        base_dn,
        scope,
        deref,
        size_limit,
        time_limit,
        types_only,
        filter,
        attributes: attrs,
    })
}

fn encode_search_entry(entry: &SearchResultEntry) -> Vec<u8> {
    let mut elements = Vec::new();
    elements.push(encode_octet_string(entry.dn.as_bytes()));
    elements.push(encode_partial_attribute_list(&entry.attributes));
    encode_constructed(TAG_SEARCH_ENTRY, &elements)
}

fn decode_search_entry(element: &BerElement) -> CoreResult<SearchResultEntry> {
    let mut reader = BerReader::new(&element.content);
    let dn = reader.read_octet_string()?;
    let attrs_elem = reader.read_element()?;
    let attributes = decode_partial_attribute_list(&attrs_elem)?;
    Ok(SearchResultEntry { dn, attributes })
}

fn encode_search_done(result: &LdapResult) -> Vec<u8> {
    encode_tagged(TAG_SEARCH_DONE, encode_ldap_result(result))
}

fn encode_search_ref(uris: &[String]) -> Vec<u8> {
    let mut list = Vec::new();
    for uri in uris {
        list.push(encode_octet_string(uri.as_bytes()));
    }
    encode_constructed(TAG_SEARCH_REF, &list)
}

fn decode_search_ref(element: &BerElement) -> CoreResult<Vec<String>> {
    let mut reader = BerReader::new(&element.content);
    let mut uris = Vec::new();
    while reader.remaining() > 0 {
        uris.push(reader.read_octet_string()?);
    }
    Ok(uris)
}

fn encode_modify_request(req: &ModifyRequest) -> CoreResult<Vec<u8>> {
    let mut elements = Vec::new();
    elements.push(encode_octet_string(req.dn.as_bytes()));
    let mut changes = Vec::new();
    for change in &req.changes {
        let mut change_elements = Vec::new();
        change_elements.push(encode_enum(change.operation.to_u32()));
        change_elements.push(encode_partial_attribute(&change.modification));
        changes.push(encode_sequence(&change_elements));
    }
    elements.push(encode_sequence(&changes));
    Ok(encode_constructed(TAG_MODIFY_REQUEST, &elements))
}

fn decode_modify_request(element: &BerElement) -> CoreResult<ModifyRequest> {
    let mut reader = BerReader::new(&element.content);
    let dn = reader.read_octet_string()?;
    let changes_elem = reader.read_element()?;
    let mut change_reader = BerReader::new(&changes_elem.content);
    let mut changes = Vec::new();
    while change_reader.remaining() > 0 {
        let change_elem = change_reader.read_element()?;
        let mut inner = BerReader::new(&change_elem.content);
        let op = ModifyOp::from_u32(inner.read_enum()? as u32)?;
        let attr_elem = inner.read_element()?;
        let modification = decode_partial_attribute(&attr_elem)?;
        changes.push(Change {
            operation: op,
            modification,
        });
    }
    Ok(ModifyRequest { dn, changes })
}

fn encode_add_request(req: &AddRequest) -> CoreResult<Vec<u8>> {
    let mut elements = Vec::new();
    elements.push(encode_octet_string(req.dn.as_bytes()));
    elements.push(encode_partial_attribute_list(&req.attributes));
    Ok(encode_constructed(TAG_ADD_REQUEST, &elements))
}

fn decode_add_request(element: &BerElement) -> CoreResult<AddRequest> {
    let mut reader = BerReader::new(&element.content);
    let dn = reader.read_octet_string()?;
    let attrs_elem = reader.read_element()?;
    let attributes = decode_partial_attribute_list(&attrs_elem)?;
    Ok(AddRequest { dn, attributes })
}

fn encode_moddn_request(req: &ModifyDnRequest) -> CoreResult<Vec<u8>> {
    let mut elements = Vec::new();
    elements.push(encode_octet_string(req.dn.as_bytes()));
    elements.push(encode_octet_string(req.new_rdn.as_bytes()));
    elements.push(encode_boolean(req.delete_old_rdn));
    if let Some(superior) = &req.new_superior {
        elements.push(encode_tagged(0x80, superior.as_bytes().to_vec()));
    }
    Ok(encode_constructed(TAG_MODDN_REQUEST, &elements))
}

fn decode_moddn_request(element: &BerElement) -> CoreResult<ModifyDnRequest> {
    let mut reader = BerReader::new(&element.content);
    let dn = reader.read_octet_string()?;
    let new_rdn = reader.read_octet_string()?;
    let delete_old_rdn = reader.read_boolean()?;
    let new_superior = if reader.remaining() > 0 {
        let elem = reader.read_element()?;
        if elem.tag == 0x80 {
            Some(String::from_utf8_lossy(&elem.content).to_string())
        } else {
            None
        }
    } else {
        None
    };
    Ok(ModifyDnRequest {
        dn,
        new_rdn,
        delete_old_rdn,
        new_superior,
    })
}

fn encode_compare_request(req: &CompareRequest) -> CoreResult<Vec<u8>> {
    let mut elements = Vec::new();
    elements.push(encode_octet_string(req.dn.as_bytes()));
    elements.push(encode_ava(&req.ava));
    Ok(encode_constructed(TAG_COMPARE_REQUEST, &elements))
}

fn decode_compare_request(element: &BerElement) -> CoreResult<CompareRequest> {
    let mut reader = BerReader::new(&element.content);
    let dn = reader.read_octet_string()?;
    let ava_elem = reader.read_element()?;
    let ava = decode_ava(&ava_elem)?;
    Ok(CompareRequest { dn, ava })
}

fn encode_extended_request(req: &ExtendedRequest) -> CoreResult<Vec<u8>> {
    let mut elements = Vec::new();
    elements.push(encode_tagged(0x80, req.name.as_bytes().to_vec()));
    if let Some(value) = &req.value {
        elements.push(encode_tagged(0x81, value.clone()));
    }
    Ok(encode_constructed(TAG_EXTENDED_REQUEST, &elements))
}

fn decode_extended_request(element: &BerElement) -> CoreResult<ExtendedRequest> {
    let mut reader = BerReader::new(&element.content);
    let name_elem = reader.read_element()?;
    if name_elem.tag != 0x80 {
        return Err(CoreError::Parse("invalid extended request".to_string()));
    }
    let name = String::from_utf8_lossy(&name_elem.content).to_string();
    let value = if reader.remaining() > 0 {
        let val_elem = reader.read_element()?;
        if val_elem.tag == 0x81 {
            Some(val_elem.content)
        } else {
            None
        }
    } else {
        None
    };
    Ok(ExtendedRequest { name, value })
}

fn encode_extended_response(resp: &ExtendedResponse) -> CoreResult<Vec<u8>> {
    let mut elements = encode_ldap_result(&resp.result);
    if let Some(name) = &resp.name {
        elements.extend_from_slice(&encode_tagged(0x8a, name.as_bytes().to_vec()));
    }
    if let Some(value) = &resp.value {
        elements.extend_from_slice(&encode_tagged(0x8b, value.clone()));
    }
    Ok(encode_tagged(TAG_EXTENDED_RESPONSE, elements))
}

fn decode_extended_response(element: &BerElement) -> CoreResult<ExtendedResponse> {
    let mut reader = BerReader::new(&element.content);
    let result = decode_ldap_result_from_reader(&mut reader)?;
    let mut name = None;
    let mut value = None;
    while reader.remaining() > 0 {
        let elem = reader.read_element()?;
        match elem.tag {
            0x8a => name = Some(String::from_utf8_lossy(&elem.content).to_string()),
            0x8b => value = Some(elem.content),
            _ => {}
        }
    }
    Ok(ExtendedResponse {
        result,
        name,
        value,
    })
}

fn encode_ldap_result(result: &LdapResult) -> Vec<u8> {
    let mut elements = Vec::new();
    elements.push(encode_enum(result.code.to_u32()));
    elements.push(encode_octet_string(result.matched_dn.as_bytes()));
    elements.push(encode_octet_string(result.message.as_bytes()));
    if !result.referrals.is_empty() {
        let mut referrals = Vec::new();
        for uri in &result.referrals {
            referrals.push(encode_octet_string(uri.as_bytes()));
        }
        let seq = encode_sequence(&referrals);
        elements.push(encode_tagged(0xa3, seq));
    }
    let mut content = Vec::new();
    for elem in elements {
        content.extend_from_slice(&elem);
    }
    content
}

fn decode_ldap_result(element: &BerElement) -> CoreResult<LdapResult> {
    let mut reader = BerReader::new(&element.content);
    decode_ldap_result_from_reader(&mut reader)
}

fn decode_ldap_result_from_reader(reader: &mut BerReader) -> CoreResult<LdapResult> {
    let code = ResultCode::from_u32(reader.read_enum()? as u32);
    let matched_dn = reader.read_octet_string()?;
    let message = reader.read_octet_string()?;
    let mut referrals = Vec::new();
    if reader.remaining() > 0 {
        let elem = reader.read_element()?;
        if elem.tag == 0xa3 {
            let mut ref_reader = BerReader::new(&elem.content);
            while ref_reader.remaining() > 0 {
                referrals.push(ref_reader.read_octet_string()?);
            }
        }
    }
    Ok(LdapResult {
        code,
        matched_dn,
        message,
        referrals,
    })
}

fn encode_controls(controls: &[Control]) -> Vec<u8> {
    let mut list = Vec::new();
    for control in controls {
        let mut elements = Vec::new();
        elements.push(encode_octet_string(control.oid.as_bytes()));
        if control.critical {
            elements.push(encode_boolean(true));
        }
        if let Some(value) = &control.value {
            elements.push(encode_octet_string(value));
        }
        list.push(encode_sequence(&elements));
    }
    let seq = encode_sequence(&list);
    encode_tagged(0xa0, seq)
}

fn decode_controls(element: &BerElement) -> CoreResult<Vec<Control>> {
    if element.tag != 0xa0 {
        return Err(CoreError::Parse("invalid controls".to_string()));
    }
    let mut reader = BerReader::new(&element.content);
    let controls_seq = reader.read_element()?;
    let mut controls_reader = BerReader::new(&controls_seq.content);
    let mut controls = Vec::new();
    while controls_reader.remaining() > 0 {
        let control_elem = controls_reader.read_element()?;
        let mut inner = BerReader::new(&control_elem.content);
        let oid = inner.read_octet_string()?;
        let mut critical = false;
        let mut value = None;
        while inner.remaining() > 0 {
            let elem = inner.read_element()?;
            match elem.tag {
                TAG_BOOLEAN => critical = decode_boolean_content(&elem.content)?,
                TAG_OCTET_STRING => value = Some(elem.content),
                _ => {}
            }
        }
        controls.push(Control {
            oid,
            critical,
            value,
        });
    }
    Ok(controls)
}

fn encode_partial_attribute_list(attributes: &[Attribute]) -> Vec<u8> {
    let mut list = Vec::new();
    for attr in attributes {
        list.push(encode_partial_attribute(attr));
    }
    encode_sequence(&list)
}

fn decode_partial_attribute_list(element: &BerElement) -> CoreResult<Vec<Attribute>> {
    let mut reader = BerReader::new(&element.content);
    let mut attrs = Vec::new();
    while reader.remaining() > 0 {
        let elem = reader.read_element()?;
        attrs.push(decode_partial_attribute(&elem)?);
    }
    Ok(attrs)
}

fn encode_partial_attribute(attr: &Attribute) -> Vec<u8> {
    let mut elements = Vec::new();
    elements.push(encode_octet_string(attr.name.as_bytes()));
    let mut values = Vec::new();
    for value in &attr.values {
        values.push(encode_octet_string(value));
    }
    elements.push(encode_set(&values));
    encode_sequence(&elements)
}

fn decode_partial_attribute(element: &BerElement) -> CoreResult<Attribute> {
    let mut reader = BerReader::new(&element.content);
    let name = reader.read_octet_string()?;
    let values_elem = reader.read_element()?;
    let mut values_reader = BerReader::new(&values_elem.content);
    let mut values = Vec::new();
    while values_reader.remaining() > 0 {
        let val_elem = values_reader.read_element()?;
        values.push(val_elem.content);
    }
    Ok(Attribute { name, values })
}

fn encode_ava(ava: &AttributeValueAssertion) -> Vec<u8> {
    let mut elements = Vec::new();
    elements.push(encode_octet_string(ava.attribute.as_bytes()));
    elements.push(encode_octet_string(&ava.value));
    encode_sequence(&elements)
}

fn decode_ava(element: &BerElement) -> CoreResult<AttributeValueAssertion> {
    let mut reader = BerReader::new(&element.content);
    let attribute = reader.read_octet_string()?;
    let value = reader.read_octet_string_bytes()?;
    Ok(AttributeValueAssertion { attribute, value })
}

fn encode_filter(filter: &Filter) -> CoreResult<Vec<u8>> {
    Ok(match filter {
        Filter::And(items) => encode_filter_list(TAG_FILTER_AND, items)?,
        Filter::Or(items) => encode_filter_list(TAG_FILTER_OR, items)?,
        Filter::Not(item) => {
            let inner = encode_filter(item)?;
            encode_tagged(TAG_FILTER_NOT, inner)
        }
        Filter::Equality(ava) => encode_tagged(TAG_FILTER_EQUALITY, encode_ava(ava)),
        Filter::Substrings {
            attribute,
            substrings,
        } => {
            let mut elements = Vec::new();
            elements.push(encode_octet_string(attribute.as_bytes()));
            let mut subs = Vec::new();
            for sub in substrings {
                let (tag, value) = match sub {
                    Substring::Initial(v) => (0x80, v.as_bytes().to_vec()),
                    Substring::Any(v) => (0x81, v.as_bytes().to_vec()),
                    Substring::Final(v) => (0x82, v.as_bytes().to_vec()),
                };
                subs.push(encode_tagged(tag, value));
            }
            elements.push(encode_sequence(&subs));
            encode_tagged(TAG_FILTER_SUBSTRINGS, encode_sequence(&elements))
        }
        Filter::GreaterOrEqual(ava) => encode_tagged(TAG_FILTER_GE, encode_ava(ava)),
        Filter::LessOrEqual(ava) => encode_tagged(TAG_FILTER_LE, encode_ava(ava)),
        Filter::Present(attr) => encode_tagged(TAG_FILTER_PRESENT, attr.as_bytes().to_vec()),
        Filter::Approx(ava) => encode_tagged(TAG_FILTER_APPROX, encode_ava(ava)),
        Filter::Extensible(ext) => {
            let mut elements = Vec::new();
            if let Some(rule) = &ext.matching_rule {
                elements.push(encode_tagged(0x81, rule.as_bytes().to_vec()));
            }
            if let Some(attr) = &ext.attribute {
                elements.push(encode_tagged(0x82, attr.as_bytes().to_vec()));
            }
            elements.push(encode_tagged(0x83, ext.value.clone()));
            if ext.dn_attributes {
                elements.push(encode_tagged(0x84, vec![0xff]));
            }
            encode_tagged(TAG_FILTER_EXTENSIBLE, encode_sequence(&elements))
        }
    })
}

fn encode_filter_list(tag: u8, items: &[Filter]) -> CoreResult<Vec<u8>> {
    let mut list = Vec::new();
    for item in items {
        list.push(encode_filter(item)?);
    }
    Ok(encode_tagged(tag, encode_sequence(&list)))
}

fn decode_filter(element: BerElement) -> CoreResult<Filter> {
    match element.tag {
        TAG_FILTER_AND => {
            let mut reader = BerReader::new(&element.content);
            let mut filters = Vec::new();
            while reader.remaining() > 0 {
                filters.push(decode_filter(reader.read_element()?)?);
            }
            Ok(Filter::And(filters))
        }
        TAG_FILTER_OR => {
            let mut reader = BerReader::new(&element.content);
            let mut filters = Vec::new();
            while reader.remaining() > 0 {
                filters.push(decode_filter(reader.read_element()?)?);
            }
            Ok(Filter::Or(filters))
        }
        TAG_FILTER_NOT => {
            let mut reader = BerReader::new(&element.content);
            let inner = decode_filter(reader.read_element()?)?;
            Ok(Filter::Not(Box::new(inner)))
        }
        TAG_FILTER_EQUALITY => {
            let ava = decode_ava(&element)?;
            Ok(Filter::Equality(ava))
        }
        TAG_FILTER_SUBSTRINGS => {
            let mut reader = BerReader::new(&element.content);
            let attribute = reader.read_octet_string()?;
            let subs_elem = reader.read_element()?;
            let mut sub_reader = BerReader::new(&subs_elem.content);
            let mut substrings = Vec::new();
            while sub_reader.remaining() > 0 {
                let sub = sub_reader.read_element()?;
                match sub.tag {
                    0x80 => substrings.push(Substring::Initial(
                        String::from_utf8_lossy(&sub.content).to_string(),
                    )),
                    0x81 => substrings.push(Substring::Any(
                        String::from_utf8_lossy(&sub.content).to_string(),
                    )),
                    0x82 => substrings.push(Substring::Final(
                        String::from_utf8_lossy(&sub.content).to_string(),
                    )),
                    _ => {}
                }
            }
            Ok(Filter::Substrings {
                attribute,
                substrings,
            })
        }
        TAG_FILTER_GE => Ok(Filter::GreaterOrEqual(decode_ava(&element)?)),
        TAG_FILTER_LE => Ok(Filter::LessOrEqual(decode_ava(&element)?)),
        TAG_FILTER_PRESENT => Ok(Filter::Present(
            String::from_utf8_lossy(&element.content).to_string(),
        )),
        TAG_FILTER_APPROX => Ok(Filter::Approx(decode_ava(&element)?)),
        TAG_FILTER_EXTENSIBLE => {
            let mut reader = BerReader::new(&element.content);
            let mut matching_rule = None;
            let mut attribute = None;
            let mut value = Vec::new();
            let mut dn_attributes = false;
            while reader.remaining() > 0 {
                let elem = reader.read_element()?;
                match elem.tag {
                    0x81 => {
                        matching_rule = Some(String::from_utf8_lossy(&elem.content).to_string())
                    }
                    0x82 => attribute = Some(String::from_utf8_lossy(&elem.content).to_string()),
                    0x83 => value = elem.content,
                    0x84 => dn_attributes = !elem.content.is_empty() && elem.content[0] != 0,
                    _ => {}
                }
            }
            Ok(Filter::Extensible(ExtensibleMatch {
                matching_rule,
                attribute,
                value,
                dn_attributes,
            }))
        }
        _ => Err(CoreError::Parse("invalid filter".to_string())),
    }
}

impl SearchScope {
    fn to_u32(self) -> u32 {
        match self {
            SearchScope::Base => 0,
            SearchScope::One => 1,
            SearchScope::Subtree => 2,
        }
    }

    fn from_u32(value: u32) -> CoreResult<Self> {
        match value {
            0 => Ok(SearchScope::Base),
            1 => Ok(SearchScope::One),
            2 => Ok(SearchScope::Subtree),
            _ => Err(CoreError::Parse("invalid scope".to_string())),
        }
    }
}

impl DerefAliases {
    fn to_u32(self) -> u32 {
        match self {
            DerefAliases::Never => 0,
            DerefAliases::InSearching => 1,
            DerefAliases::FindingBase => 2,
            DerefAliases::Always => 3,
        }
    }

    fn from_u32(value: u32) -> CoreResult<Self> {
        match value {
            0 => Ok(DerefAliases::Never),
            1 => Ok(DerefAliases::InSearching),
            2 => Ok(DerefAliases::FindingBase),
            3 => Ok(DerefAliases::Always),
            _ => Err(CoreError::Parse("invalid deref".to_string())),
        }
    }
}

impl ModifyOp {
    fn to_u32(self) -> u32 {
        match self {
            ModifyOp::Add => 0,
            ModifyOp::Delete => 1,
            ModifyOp::Replace => 2,
        }
    }

    fn from_u32(value: u32) -> CoreResult<Self> {
        match value {
            0 => Ok(ModifyOp::Add),
            1 => Ok(ModifyOp::Delete),
            2 => Ok(ModifyOp::Replace),
            _ => Err(CoreError::Parse("invalid modify op".to_string())),
        }
    }
}

fn read_ber_message<T: StreamTransport>(transport: &mut T) -> CoreResult<Vec<u8>> {
    let mut tag = [0u8; 1];
    transport.read_exact(&mut tag)?;
    let mut len_byte = [0u8; 1];
    transport.read_exact(&mut len_byte)?;
    let mut len = len_byte[0] as usize;
    let mut len_bytes = Vec::new();
    if len_byte[0] & 0x80 != 0 {
        let count = (len_byte[0] & 0x7f) as usize;
        if count == 0 {
            return Err(CoreError::Parse(
                "indefinite length not supported".to_string(),
            ));
        }
        if count > std::mem::size_of::<usize>() {
            return Err(CoreError::Parse("invalid ldap length".to_string()));
        }
        len_bytes.resize(count, 0);
        transport.read_exact(&mut len_bytes)?;
        len = 0;
        for b in &len_bytes {
            len = len
                .checked_mul(256)
                .and_then(|value| value.checked_add(*b as usize))
                .ok_or_else(|| CoreError::Parse("invalid ldap length".to_string()))?;
        }
    }
    if len > MAX_BER_MESSAGE_SIZE {
        return Err(CoreError::Parse("ldap message too large".to_string()));
    }
    let mut content = vec![0u8; len];
    transport.read_exact(&mut content)?;
    let capacity = 2usize
        .checked_add(len_bytes.len())
        .and_then(|value| value.checked_add(len))
        .ok_or_else(|| CoreError::Parse("invalid ldap length".to_string()))?;
    let mut out = Vec::with_capacity(capacity);
    out.push(tag[0]);
    out.push(len_byte[0]);
    out.extend_from_slice(&len_bytes);
    out.extend_from_slice(&content);
    Ok(out)
}

async fn read_ber_message_async<T: AsyncStreamTransport>(transport: &mut T) -> CoreResult<Vec<u8>> {
    let mut tag = [0u8; 1];
    transport.read_exact(&mut tag).await?;
    let mut len_byte = [0u8; 1];
    transport.read_exact(&mut len_byte).await?;
    let mut len = len_byte[0] as usize;
    let mut len_bytes = Vec::new();
    if len_byte[0] & 0x80 != 0 {
        let count = (len_byte[0] & 0x7f) as usize;
        if count == 0 {
            return Err(CoreError::Parse(
                "indefinite length not supported".to_string(),
            ));
        }
        if count > std::mem::size_of::<usize>() {
            return Err(CoreError::Parse("invalid ldap length".to_string()));
        }
        len_bytes.resize(count, 0);
        transport.read_exact(&mut len_bytes).await?;
        len = 0;
        for b in &len_bytes {
            len = len
                .checked_mul(256)
                .and_then(|value| value.checked_add(*b as usize))
                .ok_or_else(|| CoreError::Parse("invalid ldap length".to_string()))?;
        }
    }
    if len > MAX_BER_MESSAGE_SIZE {
        return Err(CoreError::Parse("ldap message too large".to_string()));
    }
    let mut content = vec![0u8; len];
    transport.read_exact(&mut content).await?;
    let capacity = 2usize
        .checked_add(len_bytes.len())
        .and_then(|value| value.checked_add(len))
        .ok_or_else(|| CoreError::Parse("invalid ldap length".to_string()))?;
    let mut out = Vec::with_capacity(capacity);
    out.push(tag[0]);
    out.push(len_byte[0]);
    out.extend_from_slice(&len_bytes);
    out.extend_from_slice(&content);
    Ok(out)
}

struct BerElement {
    tag: u8,
    content: Vec<u8>,
}

impl BerElement {
    fn decode(data: &[u8]) -> CoreResult<Self> {
        let mut reader = BerReader::new(data);
        let element = reader.read_element()?;
        if reader.remaining() != 0 {
            return Err(CoreError::Parse("unexpected trailing data".to_string()));
        }
        Ok(element)
    }
}

struct BerReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> BerReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn read_element(&mut self) -> CoreResult<BerElement> {
        if self.remaining() < 2 {
            return Err(CoreError::Parse("unexpected end".to_string()));
        }
        let tag = self.data[self.pos];
        self.pos += 1;
        let len_byte = self.data[self.pos];
        self.pos += 1;
        let mut len = (len_byte & 0x7f) as usize;
        if len_byte & 0x80 != 0 {
            if len == 0 {
                return Err(CoreError::Parse(
                    "indefinite length not supported".to_string(),
                ));
            }
            if len > std::mem::size_of::<usize>() {
                return Err(CoreError::Parse("invalid length".to_string()));
            }
            if self.remaining() < len {
                return Err(CoreError::Parse("invalid length".to_string()));
            }
            let mut value = 0usize;
            for _ in 0..len {
                value = value
                    .checked_mul(256)
                    .and_then(|current| current.checked_add(self.data[self.pos] as usize))
                    .ok_or_else(|| CoreError::Parse("invalid length".to_string()))?;
                self.pos += 1;
            }
            len = value;
        }
        if len > MAX_BER_MESSAGE_SIZE {
            return Err(CoreError::Parse("invalid length".to_string()));
        }
        if self.remaining() < len {
            return Err(CoreError::Parse("invalid length".to_string()));
        }
        let content = self.data[self.pos..self.pos + len].to_vec();
        self.pos += len;
        Ok(BerElement { tag, content })
    }

    fn read_integer(&mut self) -> CoreResult<i64> {
        let elem = self.read_element()?;
        if elem.tag != TAG_INTEGER {
            return Err(CoreError::Parse("expected integer".to_string()));
        }
        decode_integer_content(&elem.content)
    }

    fn read_enum(&mut self) -> CoreResult<u32> {
        let elem = self.read_element()?;
        if elem.tag != TAG_ENUM {
            return Err(CoreError::Parse("expected enum".to_string()));
        }
        Ok(decode_integer_content(&elem.content)? as u32)
    }

    fn read_boolean(&mut self) -> CoreResult<bool> {
        let elem = self.read_element()?;
        if elem.tag != TAG_BOOLEAN {
            return Err(CoreError::Parse("expected boolean".to_string()));
        }
        decode_boolean_content(&elem.content)
    }

    fn read_octet_string(&mut self) -> CoreResult<String> {
        let elem = self.read_element()?;
        if elem.tag != TAG_OCTET_STRING {
            return Err(CoreError::Parse("expected octet string".to_string()));
        }
        let value = std::str::from_utf8(&elem.content)
            .map_err(|_| CoreError::Parse("invalid utf-8 string".to_string()))?;
        Ok(value.to_string())
    }

    fn read_octet_string_bytes(&mut self) -> CoreResult<Vec<u8>> {
        let elem = self.read_element()?;
        if elem.tag != TAG_OCTET_STRING {
            return Err(CoreError::Parse("expected octet string".to_string()));
        }
        Ok(elem.content)
    }
}

fn encode_sequence(elements: &[Vec<u8>]) -> Vec<u8> {
    let mut content = Vec::new();
    for elem in elements {
        content.extend_from_slice(elem);
    }
    encode_tagged(TAG_SEQUENCE, content)
}

fn encode_constructed(tag: u8, elements: &[Vec<u8>]) -> Vec<u8> {
    let mut content = Vec::new();
    for elem in elements {
        content.extend_from_slice(elem);
    }
    encode_tagged(tag, content)
}

fn encode_set(elements: &[Vec<u8>]) -> Vec<u8> {
    let mut content = Vec::new();
    for elem in elements {
        content.extend_from_slice(elem);
    }
    encode_tagged(TAG_SET, content)
}

fn encode_integer(value: i64) -> Vec<u8> {
    encode_tagged(TAG_INTEGER, encode_integer_content(value))
}

fn encode_enum(value: u32) -> Vec<u8> {
    encode_tagged(TAG_ENUM, encode_integer_content(value as i64))
}

fn encode_boolean(value: bool) -> Vec<u8> {
    encode_tagged(TAG_BOOLEAN, vec![if value { 0xff } else { 0x00 }])
}

fn encode_octet_string(value: &[u8]) -> Vec<u8> {
    encode_tagged(TAG_OCTET_STRING, value.to_vec())
}

fn encode_tagged(tag: u8, content: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(tag);
    out.extend_from_slice(&encode_length(content.len()));
    out.extend_from_slice(&content);
    out
}

fn encode_length(len: usize) -> Vec<u8> {
    if len < 128 {
        vec![len as u8]
    } else {
        let mut bytes = Vec::new();
        let mut value = len;
        while value > 0 {
            bytes.push((value & 0xff) as u8);
            value >>= 8;
        }
        bytes.reverse();
        let mut out = Vec::with_capacity(1 + bytes.len());
        out.push(0x80 | (bytes.len() as u8));
        out.extend_from_slice(&bytes);
        out
    }
}

fn encode_integer_content(value: i64) -> Vec<u8> {
    let mut bytes = value.to_be_bytes().to_vec();
    while bytes.len() > 1 {
        let remove = if value >= 0 {
            bytes[0] == 0 && (bytes[1] & 0x80) == 0
        } else {
            bytes[0] == 0xff && (bytes[1] & 0x80) != 0
        };
        if remove {
            bytes.remove(0);
        } else {
            break;
        }
    }
    bytes
}

fn decode_integer_content(content: &[u8]) -> CoreResult<i64> {
    if content.is_empty() {
        return Err(CoreError::Parse("invalid integer".to_string()));
    }
    let mut out: i64 = if content[0] & 0x80 != 0 { -1 } else { 0 };
    for &b in content {
        out = (out << 8) | (b as i64);
    }
    Ok(out)
}

fn decode_boolean_content(content: &[u8]) -> CoreResult<bool> {
    if content.len() != 1 {
        return Err(CoreError::Parse("invalid boolean".to_string()));
    }
    Ok(content[0] != 0)
}

#[allow(dead_code)]
fn encode_oid(oid: &str) -> Vec<u8> {
    let parts: Vec<u32> = oid
        .split('.')
        .filter_map(|s| s.parse::<u32>().ok())
        .collect();
    if parts.len() < 2 {
        return vec![0];
    }
    let mut out = Vec::new();
    out.push((parts[0] * 40 + parts[1]) as u8);
    for part in parts.iter().skip(2) {
        encode_oid_part(*part, &mut out);
    }
    encode_tagged(TAG_OID, out)
}

#[allow(dead_code)]
fn encode_oid_part(mut value: u32, out: &mut Vec<u8>) {
    let mut bytes = Vec::new();
    bytes.push((value & 0x7f) as u8);
    value >>= 7;
    while value > 0 {
        bytes.push(((value & 0x7f) as u8) | 0x80);
        value >>= 7;
    }
    bytes.reverse();
    out.extend_from_slice(&bytes);
}

#[allow(dead_code)]
fn decode_oid(data: &[u8]) -> CoreResult<String> {
    if data.is_empty() {
        return Err(CoreError::Parse("invalid oid".to_string()));
    }
    let first = data[0] as u32;
    let mut parts = Vec::new();
    parts.push(first / 40);
    parts.push(first % 40);
    let mut idx = 1;
    while idx < data.len() {
        let mut value = 0u32;
        loop {
            if idx >= data.len() {
                return Err(CoreError::Parse("invalid oid".to_string()));
            }
            let byte = data[idx];
            idx += 1;
            value = (value << 7) | (byte & 0x7f) as u32;
            if byte & 0x80 == 0 {
                break;
            }
        }
        parts.push(value);
    }
    Ok(parts
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join("."))
}

fn normalize_dn(dn: &str) -> String {
    dn.split(',')
        .map(|rdn| rdn.trim())
        .filter(|rdn| !rdn.is_empty())
        .map(|rdn| {
            let mut parts = rdn.splitn(2, '=');
            let attr = parts.next().unwrap_or("").trim().to_ascii_lowercase();
            let value = parts.next().unwrap_or("").trim().to_ascii_lowercase();
            format!("{}={}", attr, value)
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn match_scope(base: &str, dn: &str, scope: SearchScope) -> bool {
    match scope {
        SearchScope::Base => dn == base,
        SearchScope::One => {
            if dn == base {
                return false;
            }
            if let Some(parent) = parent_dn(dn) {
                parent == base
            } else {
                false
            }
        }
        SearchScope::Subtree => dn == base || dn.ends_with(&format!(",{}", base)),
    }
}

fn parent_dn(dn: &str) -> Option<String> {
    let mut parts: Vec<&str> = dn.split(',').collect();
    if parts.len() <= 1 {
        return None;
    }
    parts.remove(0);
    Some(parts.join(","))
}

fn filter_match(filter: &Filter, entry: &SearchResultEntry) -> bool {
    match filter {
        Filter::And(items) => items.iter().all(|f| filter_match(f, entry)),
        Filter::Or(items) => items.iter().any(|f| filter_match(f, entry)),
        Filter::Not(item) => !filter_match(item, entry),
        Filter::Equality(ava) => attr_equals(entry, ava),
        Filter::GreaterOrEqual(ava) => attr_compare(entry, ava, |a, b| a >= b),
        Filter::LessOrEqual(ava) => attr_compare(entry, ava, |a, b| a <= b),
        Filter::Present(attr) => entry
            .attributes
            .iter()
            .any(|a| a.name.eq_ignore_ascii_case(attr)),
        Filter::Approx(ava) => attr_approx(entry, ava),
        Filter::Substrings {
            attribute,
            substrings,
        } => attr_substrings(entry, attribute, substrings),
        Filter::Extensible(ext) => {
            if let Some(attr) = &ext.attribute {
                let ava = AttributeValueAssertion {
                    attribute: attr.clone(),
                    value: ext.value.clone(),
                };
                attr_equals(entry, &ava)
            } else {
                false
            }
        }
    }
}

fn attr_equals(entry: &SearchResultEntry, ava: &AttributeValueAssertion) -> bool {
    for attr in &entry.attributes {
        if attr.name.eq_ignore_ascii_case(&ava.attribute) {
            for value in &attr.values {
                if values_equal(value, &ava.value) {
                    return true;
                }
            }
        }
    }
    false
}

fn attr_approx(entry: &SearchResultEntry, ava: &AttributeValueAssertion) -> bool {
    for attr in &entry.attributes {
        if attr.name.eq_ignore_ascii_case(&ava.attribute) {
            for value in &attr.values {
                if approx_equal(value, &ava.value) {
                    return true;
                }
            }
        }
    }
    false
}

fn attr_compare(
    entry: &SearchResultEntry,
    ava: &AttributeValueAssertion,
    cmp: impl Fn(String, String) -> bool,
) -> bool {
    let target = String::from_utf8_lossy(&ava.value).to_string();
    for attr in &entry.attributes {
        if attr.name.eq_ignore_ascii_case(&ava.attribute) {
            for value in &attr.values {
                let value = String::from_utf8_lossy(value).to_string();
                if cmp(value, target.clone()) {
                    return true;
                }
            }
        }
    }
    false
}

fn attr_substrings(entry: &SearchResultEntry, attribute: &str, substrings: &[Substring]) -> bool {
    for attr in &entry.attributes {
        if attr.name.eq_ignore_ascii_case(attribute) {
            for value in &attr.values {
                if let Ok(value_str) = std::str::from_utf8(value) {
                    if substrings_match(value_str, substrings) {
                        return true;
                    }
                }
            }
        }
    }
    false
}

fn substrings_match(value: &str, substrings: &[Substring]) -> bool {
    let mut pos = 0usize;
    for sub in substrings {
        match sub {
            Substring::Initial(s) => {
                if !value.starts_with(s) {
                    return false;
                }
                pos = s.len();
            }
            Substring::Any(s) => {
                if let Some(found) = value[pos..].find(s) {
                    pos += found + s.len();
                } else {
                    return false;
                }
            }
            Substring::Final(s) => {
                return value[pos..].ends_with(s);
            }
        }
    }
    true
}

fn values_equal(a: &[u8], b: &[u8]) -> bool {
    if let (Ok(sa), Ok(sb)) = (std::str::from_utf8(a), std::str::from_utf8(b)) {
        sa.eq_ignore_ascii_case(sb)
    } else {
        a == b
    }
}

fn approx_equal(a: &[u8], b: &[u8]) -> bool {
    let normalize = |s: &str| {
        s.chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>()
            .to_ascii_lowercase()
    };
    if let (Ok(sa), Ok(sb)) = (std::str::from_utf8(a), std::str::from_utf8(b)) {
        normalize(sa) == normalize(sb)
    } else {
        a == b
    }
}

fn filter_attributes(attrs: &[Attribute], requested: &[String]) -> Vec<Attribute> {
    if requested.iter().any(|a| a == "*") {
        return attrs.to_vec();
    }
    if requested.iter().any(|a| a == "1.1") {
        return Vec::new();
    }
    let mut out = Vec::new();
    for attr in attrs {
        if requested.iter().any(|a| a.eq_ignore_ascii_case(&attr.name)) {
            out.push(attr.clone());
        }
    }
    out
}

fn apply_change(entry: &mut SearchResultEntry, change: &Change) -> CoreResult<()> {
    match change.operation {
        ModifyOp::Add => {
            let target = entry
                .attributes
                .iter_mut()
                .find(|a| a.name.eq_ignore_ascii_case(&change.modification.name));
            if let Some(attr) = target {
                for value in &change.modification.values {
                    if !attr.values.contains(value) {
                        attr.values.push(value.clone());
                    }
                }
            } else {
                entry.attributes.push(change.modification.clone());
            }
        }
        ModifyOp::Delete => {
            if change.modification.values.is_empty() {
                entry
                    .attributes
                    .retain(|a| !a.name.eq_ignore_ascii_case(&change.modification.name));
            } else {
                if let Some(attr) = entry
                    .attributes
                    .iter_mut()
                    .find(|a| a.name.eq_ignore_ascii_case(&change.modification.name))
                {
                    attr.values
                        .retain(|v| !change.modification.values.contains(v));
                }
            }
        }
        ModifyOp::Replace => {
            if let Some(attr) = entry
                .attributes
                .iter_mut()
                .find(|a| a.name.eq_ignore_ascii_case(&change.modification.name))
            {
                attr.values = change.modification.values.clone();
            } else {
                entry.attributes.push(change.modification.clone());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ber_integer_roundtrip() {
        let value = 12345i64;
        let encoded = encode_integer(value);
        let element = BerElement::decode(&encoded).unwrap();
        let decoded = decode_integer_content(&element.content).unwrap();
        assert_eq!(value, decoded);
    }

    #[test]
    fn oid_roundtrip() {
        let oid = "1.2.840.113554.1.2.2";
        let encoded = encode_oid(oid);
        let element = BerElement::decode(&encoded).unwrap();
        let decoded = decode_oid(&element.content).unwrap();
        assert_eq!(oid, decoded);
    }

    #[test]
    fn bind_roundtrip() {
        let msg = LdapMessage {
            message_id: 1,
            op: ProtocolOp::BindRequest(BindRequest {
                version: 3,
                name: "cn=admin,dc=example,dc=com".to_string(),
                auth: BindAuth::Simple(b"secret".to_vec()),
            }),
            controls: Vec::new(),
        };
        let encoded = msg.encode().unwrap();
        let decoded = LdapMessage::decode(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn decode_rejects_out_of_range_message_id() {
        let encoded = encode_sequence(&[
            encode_integer(i32::MAX as i64 + 1),
            encode_tagged(TAG_UNBIND_REQUEST, Vec::new()),
        ]);
        assert!(LdapMessage::decode(&encoded).is_err());
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        let msg = LdapMessage {
            message_id: 1,
            op: ProtocolOp::UnbindRequest,
            controls: Vec::new(),
        };
        let mut encoded = msg.encode().unwrap();
        encoded.extend_from_slice(&[0x00, 0x00]);
        assert!(LdapMessage::decode(&encoded).is_err());
    }

    #[test]
    fn search_roundtrip() {
        let req = SearchRequest {
            base_dn: "dc=example,dc=com".to_string(),
            scope: SearchScope::Subtree,
            deref: DerefAliases::Never,
            size_limit: 0,
            time_limit: 0,
            types_only: false,
            filter: Filter::Present("cn".to_string()),
            attributes: vec!["cn".to_string(), "uid".to_string()],
        };
        let msg = LdapMessage {
            message_id: 2,
            op: ProtocolOp::SearchRequest(req.clone()),
            controls: Vec::new(),
        };
        let encoded = msg.encode().unwrap();
        let decoded = LdapMessage::decode(&encoded).unwrap();
        assert_eq!(decoded.op, ProtocolOp::SearchRequest(req));
    }

    #[test]
    fn in_memory_search() {
        let entry = SearchResultEntry {
            dn: "cn=user,dc=example,dc=com".to_string(),
            attributes: vec![
                Attribute {
                    name: "cn".to_string(),
                    values: vec![b"user".to_vec()],
                },
                Attribute {
                    name: "userPassword".to_string(),
                    values: vec![b"secret".to_vec()],
                },
            ],
        };
        let backend = InMemoryBackend::new().with_entry(entry);
        let req = SearchRequest {
            base_dn: "dc=example,dc=com".to_string(),
            scope: SearchScope::Subtree,
            deref: DerefAliases::Never,
            size_limit: 0,
            time_limit: 0,
            types_only: false,
            filter: Filter::Present("cn".to_string()),
            attributes: Vec::new(),
        };
        let results = backend.search(&req).unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn server_client_roundtrip() {
        let entry = SearchResultEntry {
            dn: "cn=user,dc=example,dc=com".to_string(),
            attributes: vec![
                Attribute {
                    name: "cn".to_string(),
                    values: vec![b"user".to_vec()],
                },
                Attribute {
                    name: "userPassword".to_string(),
                    values: vec![b"secret".to_vec()],
                },
            ],
        };
        let backend = Arc::new(InMemoryBackend::new().with_entry(entry));
        let server =
            match LdapServer::bind("127.0.0.1:0".parse().unwrap(), Timeouts::default(), backend) {
                Ok(server) => server,
                Err(CoreError::Io(err)) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                    return
                }
                Err(err) => panic!("bind: {err:?}"),
            };
        let addr = server.local_addr().unwrap();
        thread::spawn(move || {
            let _ = server.serve();
        });

        let mut client =
            LdapClient::connect(&NetAddr::from_socket(addr), Timeouts::default()).unwrap();
        let result = client
            .bind_simple("cn=user,dc=example,dc=com", "secret")
            .unwrap();
        assert_eq!(result.code, ResultCode::Success);
        let (entries, result) = client
            .search(SearchRequest {
                base_dn: "dc=example,dc=com".to_string(),
                scope: SearchScope::Subtree,
                deref: DerefAliases::Never,
                size_limit: 0,
                time_limit: 0,
                types_only: false,
                filter: Filter::Present("cn".to_string()),
                attributes: Vec::new(),
            })
            .unwrap();
        assert_eq!(result.code, ResultCode::Success);
        assert_eq!(entries.len(), 1);
    }
}
