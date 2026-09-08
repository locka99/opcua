// The OPC UA protocol types.

use puffin::agent::{AgentDescriptor, AgentName, ProtocolDescriptorConfig};
use puffin::algebra::signature::Signature;
use puffin::{atom_extract_knowledge, dummy_extract_knowledge};
use puffin::error::Error;
use puffin::trace::{Knowledge, Source};

use puffin::protocol::{Extractable, ProtocolTypes};

use serde_derive::{Deserialize, Serialize};

use crate::puffin::query::OpcuaQueryMatcher;
use crate::puffin::signature::fn_impl::CipherSuite;
use crate::puffin::signature::OPCUA_SIGNATURE;


#[derive(Clone, Copy, Debug, Hash, Serialize, Deserialize, PartialEq)]
pub enum AgentType {
    Client,
    Server,
//    User,
}

#[derive(Clone, Copy, Debug, Hash, Serialize, Deserialize, PartialEq)]
pub enum OpcuaVersion {
    V1_4, // only RSA
    V1_5, // with ECC
}

#[derive(Clone, Debug, Hash, Serialize, Deserialize, PartialEq)]
pub enum SessionSecurity {
    /// No Application Authentication, i.e. the server is configured
    /// to accept all client certificates and only use them for message security.
    SNoAA, // No client Application Authentication
    SSec,  // Normal Session Security
}

#[derive(Clone, Debug, Hash, Serialize, Deserialize, PartialEq)]
pub enum UserToken {
    Anonymous,
    Password,
    Certificate,
}

// OPC UA application configuration descriptor:
#[derive(Clone, Debug, Hash, Serialize, Deserialize, PartialEq)]
pub struct ApplicationConfig {
    pub version: OpcuaVersion,
    pub kind: AgentType,
    pub security_policy: CipherSuite,
    pub check: SessionSecurity, /// Default: SSec.
    pub utoken: UserToken,
}

impl Default for ApplicationConfig {
    fn default() -> Self {
        Self {
            version: OpcuaVersion::V1_4,
            kind: AgentType::Server,
            security_policy: CipherSuite::Basic256Sha256,
            check: SessionSecurity::SSec,
            utoken: UserToken::Certificate,
        }
    }
}

impl ApplicationConfig {

    pub fn new_client(
        name: AgentName,
    ) -> AgentDescriptor<Self> {
        AgentDescriptor {
            name,
            protocol_config: ApplicationConfig {
                kind: AgentType::Client,
                ..Self::default()
            }
        }
    }

    pub fn new_server(
        name: AgentName,
    ) -> AgentDescriptor<Self> {
        AgentDescriptor {
            name,
            protocol_config: Self::default()
        }
    }
}

impl ProtocolDescriptorConfig for ApplicationConfig {
    fn is_reusable_with(&self, other: &Self) -> bool {
        *self == *other
    }
}

// Protocol Types:

#[derive(Clone, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpcuaProtocolTypes;

impl ProtocolTypes for OpcuaProtocolTypes {
    type Matcher = OpcuaQueryMatcher;
    type PUTConfig = ApplicationConfig;

    fn signature() -> &'static Signature<Self> {
        &OPCUA_SIGNATURE
    }

    // Differential-fuzzing API (introduced by the DDYF work in the puffin base): OPC UA does not
    // participate in differential fuzzing yet, so these are neutral stubs.
    fn differential_fuzzing_whitelist() -> Option<Vec<std::any::TypeId>> {
        None
    }
    fn differential_fuzzing_claims_blacklist() -> Option<Vec<std::any::TypeId>> {
        None
    }
    fn differential_fuzzing_terms_to_eval(
        _agents: &Vec<puffin::agent::AgentDescriptor<Self::PUTConfig>>,
    ) -> Vec<puffin::algebra::Term<Self>> {
        vec![]
    }
    fn differential_fuzzing_uniformise_put_config(
        trace: puffin::trace::Trace<Self>,
    ) -> puffin::trace::Trace<Self> {
        trace
    }
    fn differential_fuzzing_filter_diff(_diff: &puffin::differential::TraceDifference) -> bool {
        true
    }
}

impl std::fmt::Display for OpcuaProtocolTypes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "")
    }
}

// For Basic Types:
dummy_extract_knowledge!(OpcuaProtocolTypes, bool);
atom_extract_knowledge!(OpcuaProtocolTypes, u8);
atom_extract_knowledge!(OpcuaProtocolTypes, u16);
atom_extract_knowledge!(OpcuaProtocolTypes, u32);
atom_extract_knowledge!(OpcuaProtocolTypes, f64);

// dummy_comparable!: implement `comparable::Comparable` on a TOP type WITHOUT recursing into its
// sub-terms (unlike `#[derive(Comparable)]`, which would force every field to be `Comparable`).
// The impl describes nothing and always reports `Unchanged` — enough to satisfy the
// `CompareKnowledge`/`EvaluatedTerm` bounds pulled in by the differential-fuzzing machinery, while
// OPC UA opts out of actual knowledge comparison.
#[macro_export]
macro_rules! dummy_comparable {
    ($($t:ty),+ $(,)?) => {$(
        impl comparable::Comparable for $t {
            type Desc = ();
            fn describe(&self) -> Self::Desc {}
            type Change = ();
            fn comparison(&self, _other: &Self) -> comparable::Changed<Self::Change> {
                comparable::Changed::Unchanged
            }
        }
    )+};
}

