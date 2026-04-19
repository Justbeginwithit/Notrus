use async_trait::async_trait;
use base64::Engine as _;
use base64::prelude::BASE64_STANDARD;
use futures::executor::block_on;
use libsignal_protocol::error::Result as SignalResult;
use libsignal_protocol::{
    CiphertextMessageType, DeviceId, GenericSignedPreKey, IdentityChange, IdentityKey,
    IdentityKeyPair, IdentityKeyStore, KeyPair, KyberPreKeyId, KyberPreKeyRecord, KyberPreKeyStore,
    PreKeyBundle, PreKeyId, PreKeyRecord, PreKeyStore, ProtocolAddress, PublicKey, SessionRecord,
    SessionStore, SessionUsabilityRequirements, SignedPreKeyId, SignedPreKeyRecord,
    SignedPreKeyStore, Timestamp, kem, message_decrypt, message_encrypt, process_prekey_bundle,
};
use openmls::credentials::{BasicCredential, CredentialWithKey};
use openmls::framing::ProcessedMessageContent;
use openmls::prelude::tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use rand_core::{OsRng, RngCore, TryRngCore as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::SystemTime;

const SIGNAL_STATE_VERSION: u32 = 1;
const MLS_STATE_VERSION: u32 = 1;
const DEFAULT_DEVICE_ID: u32 = 1;
const DEFAULT_CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "kebab-case")]
pub enum BridgeRequest {
    ProfileSnapshot,
    CreateIdentity(CreateIdentityRequest),
    RefreshMlsKeyPackage(RefreshMlsKeyPackageRequest),
    RefreshSignalBundle(RefreshSignalBundleRequest),
    SignalEncrypt(SignalEncryptRequest),
    SignalDecrypt(SignalDecryptRequest),
    SignalResetPeer(SignalResetPeerRequest),
    MlsCreateGroup(MlsCreateGroupRequest),
    MlsJoinGroup(MlsJoinGroupRequest),
    MlsEncryptMessage(MlsEncryptMessageRequest),
    MlsProcessMessage(MlsProcessMessageRequest),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateIdentityRequest {
    pub display_name: String,
    pub thread_user_id: String,
    pub username: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RefreshMlsKeyPackageRequest {
    pub mls_state: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RefreshSignalBundleRequest {
    pub signal_state: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignalEncryptRequest {
    pub local_signal_state: String,
    pub local_user_id: String,
    pub plaintext: String,
    pub remote_bundle: PublicSignalBundle,
    pub remote_user_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignalDecryptRequest {
    pub local_signal_state: String,
    pub local_user_id: String,
    pub message_kind: String,
    pub remote_user_id: String,
    pub wire_message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignalResetPeerRequest {
    pub local_signal_state: String,
    pub remote_user_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MlsCreateGroupRequest {
    pub creator_mls_state: String,
    pub creator_user_id: String,
    pub participant_key_packages: HashMap<String, PublicMlsKeyPackage>,
    pub participant_user_ids: Vec<String>,
    pub thread_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MlsJoinGroupRequest {
    pub local_mls_state: String,
    pub local_user_id: String,
    pub thread_bootstrap: MlsThreadBootstrap,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MlsEncryptMessageRequest {
    pub local_mls_state: String,
    pub plaintext: String,
    pub thread_state: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MlsProcessMessageRequest {
    pub local_mls_state: String,
    pub thread_state: String,
    pub wire_message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicSignalBundle {
    pub device_id: u32,
    pub identity_key: String,
    pub kyber_pre_key_id: u32,
    pub kyber_pre_key_public: String,
    pub kyber_pre_key_signature: String,
    pub pre_key_id: u32,
    pub pre_key_public: String,
    pub registration_id: u32,
    pub signed_pre_key_id: u32,
    pub signed_pre_key_public: String,
    pub signed_pre_key_signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicMlsKeyPackage {
    pub ciphersuite: String,
    pub key_package: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlsWelcomeEnvelope {
    pub to_user_id: String,
    pub welcome: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlsThreadBootstrap {
    pub ciphersuite: String,
    pub group_id: String,
    pub welcomes: Vec<MlsWelcomeEnvelope>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateIdentityResponse {
    pub fingerprint: String,
    pub mls_key_package: PublicMlsKeyPackage,
    pub mls_state: String,
    pub signal_bundle: PublicSignalBundle,
    pub signal_state: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RefreshMlsKeyPackageResponse {
    pub mls_key_package: PublicMlsKeyPackage,
    pub mls_state: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RefreshSignalBundleResponse {
    pub signal_bundle: PublicSignalBundle,
    pub signal_state: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignalEncryptResponse {
    pub local_signal_state: String,
    pub message_kind: String,
    pub wire_message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignalDecryptResponse {
    pub local_signal_state: String,
    pub plaintext: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignalResetPeerResponse {
    pub local_signal_state: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MlsCreateGroupResponse {
    pub creator_mls_state: String,
    pub thread_bootstrap: MlsThreadBootstrap,
    pub thread_state: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MlsJoinGroupResponse {
    pub local_mls_state: String,
    pub thread_state: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MlsEncryptMessageResponse {
    pub local_mls_state: String,
    pub thread_state: String,
    pub wire_message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MlsProcessMessageResponse {
    pub local_mls_state: String,
    pub plaintext: String,
    pub thread_state: String,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
struct SignalAddressRef {
    device_id: u32,
    name: String,
}

impl SignalAddressRef {
    fn from_protocol(address: &ProtocolAddress) -> Self {
        Self {
            device_id: address.device_id().into(),
            name: address.name().to_owned(),
        }
    }

    fn to_protocol(&self) -> Result<ProtocolAddress, String> {
        let device_id = DeviceId::new(
            self.device_id
                .try_into()
                .map_err(|_| format!("Invalid device id {}", self.device_id))?,
        )
            .map_err(|error| format!("Invalid device id {}: {error}", self.device_id))?;
        Ok(ProtocolAddress::new(self.name.clone(), device_id))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct SignalRecordRef {
    id: u32,
    serialized: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct SignalKnownIdentityRef {
    address: SignalAddressRef,
    identity_key: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct SignalSessionRef {
    address: SignalAddressRef,
    session: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct KyberUsageRef {
    base_keys: Vec<String>,
    kyber_pre_key_id: u32,
    signed_pre_key_id: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct SignalAccountState {
    core_version: String,
    device_id: u32,
    identity_key_pair: String,
    known_identities: Vec<SignalKnownIdentityRef>,
    kyber_pre_key_usage: Vec<KyberUsageRef>,
    kyber_pre_keys: Vec<SignalRecordRef>,
    next_kyber_pre_key_id: u32,
    next_pre_key_id: u32,
    next_signed_pre_key_id: u32,
    pre_keys: Vec<SignalRecordRef>,
    registration_id: u32,
    sessions: Vec<SignalSessionRef>,
    signed_pre_keys: Vec<SignalRecordRef>,
    version: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct MlsAccountState {
    core_version: String,
    ciphersuite: String,
    credential_with_key: String,
    signer: String,
    storage_snapshot: String,
    version: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct MlsThreadState {
    ciphersuite: String,
    group_id: String,
}

#[derive(Clone, Debug, Default)]
struct SerializableIdentityKeyStore {
    identity_key_pair: Vec<u8>,
    known_keys: HashMap<SignalAddressRef, Vec<u8>>,
    registration_id: u32,
}

#[derive(Clone, Debug, Default)]
struct SerializablePreKeyStore {
    pre_keys: HashMap<u32, Vec<u8>>,
}

#[derive(Clone, Debug, Default)]
struct SerializableSignedPreKeyStore {
    signed_pre_keys: HashMap<u32, Vec<u8>>,
}

#[derive(Clone, Debug, Default)]
struct SerializableKyberPreKeyStore {
    base_keys_seen: HashMap<(u32, u32), Vec<Vec<u8>>>,
    kyber_pre_keys: HashMap<u32, Vec<u8>>,
}

#[derive(Clone, Debug, Default)]
struct SerializableSessionStore {
    sessions: HashMap<SignalAddressRef, Vec<u8>>,
}

#[derive(Clone, Debug, Default)]
struct SerializableSignalProtocolStore {
    identity_store: SerializableIdentityKeyStore,
    kyber_pre_key_store: SerializableKyberPreKeyStore,
    pre_key_store: SerializablePreKeyStore,
    session_store: SerializableSessionStore,
    signed_pre_key_store: SerializableSignedPreKeyStore,
}

#[async_trait(?Send)]
impl IdentityKeyStore for SerializableIdentityKeyStore {
    async fn get_identity_key_pair(&self) -> SignalResult<IdentityKeyPair> {
        IdentityKeyPair::try_from(self.identity_key_pair.as_slice())
    }

    async fn get_local_registration_id(&self) -> SignalResult<u32> {
        Ok(self.registration_id)
    }

    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> SignalResult<IdentityChange> {
        let key = SignalAddressRef::from_protocol(address);
        let incoming = identity.serialize().into_vec();
        let changed = self
            .known_keys
            .insert(key, incoming.clone())
            .map(|existing| existing != incoming)
            .unwrap_or(false);
        Ok(IdentityChange::from_changed(changed))
    }

    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        _direction: libsignal_protocol::Direction,
    ) -> SignalResult<bool> {
        let key = SignalAddressRef::from_protocol(address);
        Ok(self
            .known_keys
            .get(&key)
            .map(|stored| stored.as_slice() == identity.serialize().as_ref())
            .unwrap_or(true))
    }

    async fn get_identity(
        &self,
        address: &ProtocolAddress,
    ) -> SignalResult<Option<IdentityKey>> {
        let key = SignalAddressRef::from_protocol(address);
        self.known_keys
            .get(&key)
            .map(|stored| IdentityKey::decode(stored))
            .transpose()
    }
}

#[async_trait(?Send)]
impl PreKeyStore for SerializablePreKeyStore {
    async fn get_pre_key(&self, prekey_id: PreKeyId) -> SignalResult<PreKeyRecord> {
        self.pre_keys
            .get(&u32::from(prekey_id))
            .ok_or(libsignal_protocol::SignalProtocolError::InvalidPreKeyId)
            .and_then(|record| PreKeyRecord::deserialize(record))
    }

    async fn save_pre_key(
        &mut self,
        prekey_id: PreKeyId,
        record: &PreKeyRecord,
    ) -> SignalResult<()> {
        self.pre_keys
            .insert(u32::from(prekey_id), record.serialize()?);
        Ok(())
    }

    async fn remove_pre_key(&mut self, prekey_id: PreKeyId) -> SignalResult<()> {
        self.pre_keys.remove(&u32::from(prekey_id));
        Ok(())
    }
}

#[async_trait(?Send)]
impl SignedPreKeyStore for SerializableSignedPreKeyStore {
    async fn get_signed_pre_key(
        &self,
        signed_prekey_id: SignedPreKeyId,
    ) -> SignalResult<SignedPreKeyRecord> {
        self.signed_pre_keys
            .get(&u32::from(signed_prekey_id))
            .ok_or(libsignal_protocol::SignalProtocolError::InvalidSignedPreKeyId)
            .and_then(|record| SignedPreKeyRecord::deserialize(record))
    }

    async fn save_signed_pre_key(
        &mut self,
        signed_prekey_id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
    ) -> SignalResult<()> {
        self.signed_pre_keys
            .insert(u32::from(signed_prekey_id), record.serialize()?);
        Ok(())
    }
}

#[async_trait(?Send)]
impl KyberPreKeyStore for SerializableKyberPreKeyStore {
    async fn get_kyber_pre_key(
        &self,
        kyber_prekey_id: KyberPreKeyId,
    ) -> SignalResult<KyberPreKeyRecord> {
        self.kyber_pre_keys
            .get(&u32::from(kyber_prekey_id))
            .ok_or(libsignal_protocol::SignalProtocolError::InvalidKyberPreKeyId)
            .and_then(|record| KyberPreKeyRecord::deserialize(record))
    }

    async fn save_kyber_pre_key(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        record: &KyberPreKeyRecord,
    ) -> SignalResult<()> {
        self.kyber_pre_keys
            .insert(u32::from(kyber_prekey_id), record.serialize()?);
        Ok(())
    }

    async fn mark_kyber_pre_key_used(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        ec_prekey_id: SignedPreKeyId,
        base_key: &PublicKey,
    ) -> SignalResult<()> {
        let base_keys = self
            .base_keys_seen
            .entry((u32::from(kyber_prekey_id), u32::from(ec_prekey_id)))
            .or_default();
        let serialized = base_key.serialize().into_vec();
        if base_keys.iter().any(|existing| existing == &serialized) {
            return Err(libsignal_protocol::SignalProtocolError::InvalidMessage(
                CiphertextMessageType::PreKey,
                "reused base key",
            ));
        }
        base_keys.push(serialized);
        Ok(())
    }
}

#[async_trait(?Send)]
impl SessionStore for SerializableSessionStore {
    async fn load_session(
        &self,
        address: &ProtocolAddress,
    ) -> SignalResult<Option<SessionRecord>> {
        self.sessions
            .get(&SignalAddressRef::from_protocol(address))
            .map(|record| SessionRecord::deserialize(record))
            .transpose()
    }

    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> SignalResult<()> {
        self.sessions.insert(
            SignalAddressRef::from_protocol(address),
            record.serialize()?,
        );
        Ok(())
    }
}

impl SerializableSignalProtocolStore {
    fn new(identity_key_pair: IdentityKeyPair, registration_id: u32) -> Self {
        Self {
            identity_store: SerializableIdentityKeyStore {
                identity_key_pair: identity_key_pair.serialize().into_vec(),
                known_keys: HashMap::new(),
                registration_id,
            },
            kyber_pre_key_store: SerializableKyberPreKeyStore::default(),
            pre_key_store: SerializablePreKeyStore::default(),
            session_store: SerializableSessionStore::default(),
            signed_pre_key_store: SerializableSignedPreKeyStore::default(),
        }
    }

    fn from_state(state: SignalAccountState) -> Result<Self, String> {
        if state.version != SIGNAL_STATE_VERSION {
            return Err(format!("Unsupported signal state version {}", state.version));
        }

        let known_keys = state
            .known_identities
            .into_iter()
            .map(|entry| Ok((entry.address, decode(&entry.identity_key)?)))
            .collect::<Result<HashMap<_, _>, String>>()?;
        let pre_keys = state
            .pre_keys
            .into_iter()
            .map(|entry| Ok((entry.id, decode(&entry.serialized)?)))
            .collect::<Result<HashMap<_, _>, String>>()?;
        let signed_pre_keys = state
            .signed_pre_keys
            .into_iter()
            .map(|entry| Ok((entry.id, decode(&entry.serialized)?)))
            .collect::<Result<HashMap<_, _>, String>>()?;
        let kyber_pre_keys = state
            .kyber_pre_keys
            .into_iter()
            .map(|entry| Ok((entry.id, decode(&entry.serialized)?)))
            .collect::<Result<HashMap<_, _>, String>>()?;
        let sessions = state
            .sessions
            .into_iter()
            .map(|entry| Ok((entry.address, decode(&entry.session)?)))
            .collect::<Result<HashMap<_, _>, String>>()?;
        let base_keys_seen = state
            .kyber_pre_key_usage
            .into_iter()
            .map(|entry| {
                Ok((
                    (entry.kyber_pre_key_id, entry.signed_pre_key_id),
                    entry
                        .base_keys
                        .into_iter()
                        .map(|value| decode(&value))
                        .collect::<Result<Vec<_>, _>>()?,
                ))
            })
            .collect::<Result<HashMap<_, _>, String>>()?;

        Ok(Self {
            identity_store: SerializableIdentityKeyStore {
                identity_key_pair: decode(&state.identity_key_pair)?,
                known_keys,
                registration_id: state.registration_id,
            },
            kyber_pre_key_store: SerializableKyberPreKeyStore {
                base_keys_seen,
                kyber_pre_keys,
            },
            pre_key_store: SerializablePreKeyStore { pre_keys },
            session_store: SerializableSessionStore { sessions },
            signed_pre_key_store: SerializableSignedPreKeyStore { signed_pre_keys },
        })
    }

    fn to_json(&self, device_id: u32, next_pre_key_id: u32, next_signed_pre_key_id: u32, next_kyber_pre_key_id: u32) -> Result<String, String> {
        serde_json::to_string(&self.to_state(device_id, next_pre_key_id, next_signed_pre_key_id, next_kyber_pre_key_id))
            .map_err(|error| format!("Unable to encode signal state: {error}"))
    }

    fn to_state(
        &self,
        device_id: u32,
        next_pre_key_id: u32,
        next_signed_pre_key_id: u32,
        next_kyber_pre_key_id: u32,
    ) -> SignalAccountState {
        let mut known_identities = self
            .identity_store
            .known_keys
            .iter()
            .map(|(address, identity_key)| SignalKnownIdentityRef {
                address: address.clone(),
                identity_key: encode(identity_key),
            })
            .collect::<Vec<_>>();
        known_identities.sort_by(|left, right| {
            left.address
                .name
                .cmp(&right.address.name)
                .then(left.address.device_id.cmp(&right.address.device_id))
        });

        let mut pre_keys = self
            .pre_key_store
            .pre_keys
            .iter()
            .map(|(id, serialized)| SignalRecordRef {
                id: *id,
                serialized: encode(serialized),
            })
            .collect::<Vec<_>>();
        pre_keys.sort_by_key(|entry| entry.id);

        let mut signed_pre_keys = self
            .signed_pre_key_store
            .signed_pre_keys
            .iter()
            .map(|(id, serialized)| SignalRecordRef {
                id: *id,
                serialized: encode(serialized),
            })
            .collect::<Vec<_>>();
        signed_pre_keys.sort_by_key(|entry| entry.id);

        let mut kyber_pre_keys = self
            .kyber_pre_key_store
            .kyber_pre_keys
            .iter()
            .map(|(id, serialized)| SignalRecordRef {
                id: *id,
                serialized: encode(serialized),
            })
            .collect::<Vec<_>>();
        kyber_pre_keys.sort_by_key(|entry| entry.id);

        let mut sessions = self
            .session_store
            .sessions
            .iter()
            .map(|(address, session)| SignalSessionRef {
                address: address.clone(),
                session: encode(session),
            })
            .collect::<Vec<_>>();
        sessions.sort_by(|left, right| {
            left.address
                .name
                .cmp(&right.address.name)
                .then(left.address.device_id.cmp(&right.address.device_id))
        });

        let mut kyber_pre_key_usage = self
            .kyber_pre_key_store
            .base_keys_seen
            .iter()
            .map(|((kyber_pre_key_id, signed_pre_key_id), base_keys)| KyberUsageRef {
                base_keys: base_keys.iter().map(encode).collect(),
                kyber_pre_key_id: *kyber_pre_key_id,
                signed_pre_key_id: *signed_pre_key_id,
            })
            .collect::<Vec<_>>();
        kyber_pre_key_usage.sort_by(|left, right| {
            left.kyber_pre_key_id
                .cmp(&right.kyber_pre_key_id)
                .then(left.signed_pre_key_id.cmp(&right.signed_pre_key_id))
        });

        SignalAccountState {
            core_version: crate::core_profile_snapshot()["coreVersion"]
                .as_str()
                .unwrap_or("notrus-protocol-core")
                .to_owned(),
            device_id,
            identity_key_pair: encode(&self.identity_store.identity_key_pair),
            known_identities,
            kyber_pre_key_usage,
            kyber_pre_keys,
            next_kyber_pre_key_id,
            next_pre_key_id,
            next_signed_pre_key_id,
            pre_keys,
            registration_id: self.identity_store.registration_id,
            sessions,
            signed_pre_keys,
            version: SIGNAL_STATE_VERSION,
        }
    }
}

#[derive(Clone)]
struct SignalIdentityMaterial {
    bundle: PublicSignalBundle,
    device_id: u32,
    next_kyber_pre_key_id: u32,
    next_pre_key_id: u32,
    next_signed_pre_key_id: u32,
    store: SerializableSignalProtocolStore,
}

fn encode(bytes: impl AsRef<[u8]>) -> String {
    BASE64_STANDARD.encode(bytes.as_ref())
}

fn decode(value: &str) -> Result<Vec<u8>, String> {
    BASE64_STANDARD
        .decode(value)
        .map_err(|error| format!("Invalid base64 payload: {error}"))
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

fn identity_fingerprint(signal_identity_key: &[u8]) -> String {
    hex(Sha256::digest(signal_identity_key))
}

fn create_signal_identity_material() -> Result<SignalIdentityMaterial, String> {
    let mut csprng = OsRng.unwrap_err();
    let registration_id = csprng.next_u32();
    let identity_key_pair = IdentityKeyPair::generate(&mut csprng);
    let mut store = SerializableSignalProtocolStore::new(identity_key_pair, registration_id);

    let pre_key_id = 1u32;
    let signed_pre_key_id = 1u32;
    let kyber_pre_key_id = 1u32;

    let pre_key_pair = KeyPair::generate(&mut csprng);
    let signed_pre_key_pair = KeyPair::generate(&mut csprng);
    let identity = block_on(store.identity_store.get_identity_key_pair())
        .map_err(|error| format!("Unable to load signal identity: {error}"))?;
    let signed_pre_key_signature = identity
        .private_key()
        .calculate_signature(&signed_pre_key_pair.public_key.serialize(), &mut csprng)
        .map_err(|error| format!("Unable to sign signal signed pre-key: {error}"))?;
    let kyber_pre_key_record = KyberPreKeyRecord::generate(
        kem::KeyType::Kyber1024,
        KyberPreKeyId::from(kyber_pre_key_id),
        identity.private_key(),
    )
    .map_err(|error| format!("Unable to generate Kyber pre-key: {error}"))?;

    block_on(store.pre_key_store.save_pre_key(PreKeyId::from(pre_key_id), &PreKeyRecord::new(PreKeyId::from(pre_key_id), &pre_key_pair)))
        .map_err(|error| format!("Unable to store signal pre-key: {error}"))?;
    block_on(store.signed_pre_key_store.save_signed_pre_key(
        SignedPreKeyId::from(signed_pre_key_id),
        &SignedPreKeyRecord::new(
            SignedPreKeyId::from(signed_pre_key_id),
            Timestamp::from_epoch_millis(42),
            &signed_pre_key_pair,
            &signed_pre_key_signature,
        ),
    ))
    .map_err(|error| format!("Unable to store signal signed pre-key: {error}"))?;
    block_on(store.kyber_pre_key_store.save_kyber_pre_key(
        KyberPreKeyId::from(kyber_pre_key_id),
        &kyber_pre_key_record,
    ))
    .map_err(|error| format!("Unable to store signal Kyber pre-key: {error}"))?;

    let bundle = PublicSignalBundle {
        device_id: DEFAULT_DEVICE_ID,
        identity_key: encode(identity.identity_key().serialize()),
        kyber_pre_key_id,
        kyber_pre_key_public: encode(
            kyber_pre_key_record
                .public_key()
                .map_err(|error| format!("Unable to expose Kyber pre-key: {error}"))?
                .serialize(),
        ),
        kyber_pre_key_signature: encode(
            kyber_pre_key_record
                .signature()
                .map_err(|error| format!("Unable to expose Kyber signature: {error}"))?,
        ),
        pre_key_id,
        pre_key_public: encode(pre_key_pair.public_key.serialize()),
        registration_id,
        signed_pre_key_id,
        signed_pre_key_public: encode(signed_pre_key_pair.public_key.serialize()),
        signed_pre_key_signature: encode(signed_pre_key_signature),
    };

    Ok(SignalIdentityMaterial {
        bundle,
        device_id: DEFAULT_DEVICE_ID,
        next_kyber_pre_key_id: kyber_pre_key_id + 1,
        next_pre_key_id: pre_key_id + 1,
        next_signed_pre_key_id: signed_pre_key_id + 1,
        store,
    })
}

fn refresh_signal_bundle(request: RefreshSignalBundleRequest) -> Result<RefreshSignalBundleResponse, String> {
    let (mut store, state) = signal_store_from_json(&request.signal_state)?;
    let mut csprng = OsRng.unwrap_err();
    let identity = block_on(store.identity_store.get_identity_key_pair())
        .map_err(|error| format!("Unable to load signal identity for bundle refresh: {error}"))?;

    let pre_key_id = state.next_pre_key_id;
    let signed_pre_key_id = state.next_signed_pre_key_id;
    let kyber_pre_key_id = state.next_kyber_pre_key_id;

    let pre_key_pair = KeyPair::generate(&mut csprng);
    let signed_pre_key_pair = KeyPair::generate(&mut csprng);
    let signed_pre_key_signature = identity
        .private_key()
        .calculate_signature(&signed_pre_key_pair.public_key.serialize(), &mut csprng)
        .map_err(|error| format!("Unable to sign refreshed signal signed pre-key: {error}"))?;
    let kyber_pre_key_record = KyberPreKeyRecord::generate(
        kem::KeyType::Kyber1024,
        KyberPreKeyId::from(kyber_pre_key_id),
        identity.private_key(),
    )
    .map_err(|error| format!("Unable to refresh Kyber pre-key: {error}"))?;

    block_on(store.pre_key_store.save_pre_key(
        PreKeyId::from(pre_key_id),
        &PreKeyRecord::new(PreKeyId::from(pre_key_id), &pre_key_pair),
    ))
    .map_err(|error| format!("Unable to store refreshed signal pre-key: {error}"))?;
    block_on(store.signed_pre_key_store.save_signed_pre_key(
        SignedPreKeyId::from(signed_pre_key_id),
        &SignedPreKeyRecord::new(
            SignedPreKeyId::from(signed_pre_key_id),
            Timestamp::from_epoch_millis(
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .map_err(|error| format!("Unable to read system time for signal signed pre-key refresh: {error}"))?
                    .as_millis() as u64,
            ),
            &signed_pre_key_pair,
            &signed_pre_key_signature,
        ),
    ))
    .map_err(|error| format!("Unable to store refreshed signal signed pre-key: {error}"))?;
    block_on(store.kyber_pre_key_store.save_kyber_pre_key(
        KyberPreKeyId::from(kyber_pre_key_id),
        &kyber_pre_key_record,
    ))
    .map_err(|error| format!("Unable to store refreshed signal Kyber pre-key: {error}"))?;

    Ok(RefreshSignalBundleResponse {
        signal_bundle: PublicSignalBundle {
            device_id: state.device_id,
            identity_key: encode(identity.identity_key().serialize()),
            kyber_pre_key_id,
            kyber_pre_key_public: encode(
                kyber_pre_key_record
                    .public_key()
                    .map_err(|error| format!("Unable to expose refreshed Kyber pre-key: {error}"))?
                    .serialize(),
            ),
            kyber_pre_key_signature: encode(
                kyber_pre_key_record
                    .signature()
                    .map_err(|error| format!("Unable to expose refreshed Kyber signature: {error}"))?,
            ),
            pre_key_id,
            pre_key_public: encode(pre_key_pair.public_key.serialize()),
            registration_id: state.registration_id,
            signed_pre_key_id,
            signed_pre_key_public: encode(signed_pre_key_pair.public_key.serialize()),
            signed_pre_key_signature: encode(signed_pre_key_signature),
        },
        signal_state: store.to_json(
            state.device_id,
            pre_key_id + 1,
            signed_pre_key_id + 1,
            kyber_pre_key_id + 1,
        )?,
    })
}

fn signal_store_from_json(json: &str) -> Result<(SerializableSignalProtocolStore, SignalAccountState), String> {
    let state: SignalAccountState =
        serde_json::from_str(json).map_err(|error| format!("Invalid signal state: {error}"))?;
    let store = SerializableSignalProtocolStore::from_state(state.clone())?;
    Ok((store, state))
}

fn signal_bundle_to_libsignal(bundle: &PublicSignalBundle) -> Result<PreKeyBundle, String> {
    let device_id = DeviceId::new(
        bundle
            .device_id
            .try_into()
            .map_err(|_| format!("Invalid signal device id {}", bundle.device_id))?,
    )
        .map_err(|error| format!("Invalid signal device id {}: {error}", bundle.device_id))?;
    PreKeyBundle::new(
        bundle.registration_id,
        device_id,
        Some((
            PreKeyId::from(bundle.pre_key_id),
            PublicKey::deserialize(&decode(&bundle.pre_key_public)?)
                .map_err(|error| format!("Invalid signal pre-key bundle public key: {error}"))?,
        )),
        SignedPreKeyId::from(bundle.signed_pre_key_id),
        PublicKey::deserialize(&decode(&bundle.signed_pre_key_public)?)
            .map_err(|error| format!("Invalid signal signed pre-key public key: {error}"))?,
        decode(&bundle.signed_pre_key_signature)?,
        KyberPreKeyId::from(bundle.kyber_pre_key_id),
        kem::PublicKey::deserialize(&decode(&bundle.kyber_pre_key_public)?)
            .map_err(|error| format!("Invalid signal Kyber pre-key public key: {error}"))?,
        decode(&bundle.kyber_pre_key_signature)?,
        IdentityKey::decode(&decode(&bundle.identity_key)?)
            .map_err(|error| format!("Invalid signal identity key: {error}"))?,
    )
    .map_err(|error| format!("Unable to construct signal pre-key bundle: {error}"))
}

fn signal_session_usable(store: &SerializableSignalProtocolStore, remote_address: &ProtocolAddress) -> Result<bool, String> {
    let maybe_session = block_on(store.session_store.load_session(remote_address))
        .map_err(|error| format!("Unable to load signal session: {error}"))?;
    let Some(session) = maybe_session else {
        return Ok(false);
    };
    session
        .has_usable_sender_chain(
            SystemTime::now(),
            SessionUsabilityRequirements::NotStale | SessionUsabilityRequirements::EstablishedWithPqxdh,
        )
        .map_err(|error| format!("Unable to inspect signal session usability: {error}"))
}

fn signal_encrypt(request: SignalEncryptRequest) -> Result<SignalEncryptResponse, String> {
    let (mut store, state) = signal_store_from_json(&request.local_signal_state)?;
    let local_address = SignalAddressRef {
        device_id: state.device_id,
        name: request.local_user_id.clone(),
    }
    .to_protocol()?;
    let remote_address = SignalAddressRef {
        device_id: request.remote_bundle.device_id,
        name: request.remote_user_id.clone(),
    }
    .to_protocol()?;
    let mut csprng = OsRng.unwrap_err();

    if !signal_session_usable(&store, &remote_address)? {
        let bundle = signal_bundle_to_libsignal(&request.remote_bundle)?;
        block_on(process_prekey_bundle(
            &remote_address,
            &mut store.session_store,
            &mut store.identity_store,
            &bundle,
            SystemTime::now(),
            &mut csprng,
        ))
        .map_err(|error| format!("Unable to establish a PQXDH session: {error}"))?;
    }

    let outbound = block_on(message_encrypt(
        request.plaintext.as_bytes(),
        &remote_address,
        &local_address,
        &mut store.session_store,
        &mut store.identity_store,
        SystemTime::now(),
        &mut csprng,
    ))
    .map_err(|error| format!("Unable to encrypt the Signal message: {error}"))?;

    Ok(SignalEncryptResponse {
        local_signal_state: store.to_json(
            state.device_id,
            state.next_pre_key_id,
            state.next_signed_pre_key_id,
            state.next_kyber_pre_key_id,
        )?,
        message_kind: match outbound.message_type() {
            CiphertextMessageType::PreKey => "signal-prekey",
            CiphertextMessageType::Whisper => "signal-whisper",
            CiphertextMessageType::SenderKey => "signal-sender-key",
            CiphertextMessageType::Plaintext => "signal-plaintext",
        }
        .to_owned(),
        wire_message: encode(outbound.serialize()),
    })
}

fn signal_decrypt(request: SignalDecryptRequest) -> Result<SignalDecryptResponse, String> {
    let (mut store, state) = signal_store_from_json(&request.local_signal_state)?;
    let local_address = SignalAddressRef {
        device_id: state.device_id,
        name: request.local_user_id.clone(),
    }
    .to_protocol()?;
    let remote_address = SignalAddressRef {
        device_id: DEFAULT_DEVICE_ID,
        name: request.remote_user_id.clone(),
    }
    .to_protocol()?;
    let raw_message = decode(&request.wire_message)?;
    let message = match request.message_kind.as_str() {
        "signal-prekey" => libsignal_protocol::CiphertextMessage::PreKeySignalMessage(
            libsignal_protocol::PreKeySignalMessage::try_from(raw_message.as_slice())
                .map_err(|error| format!("Invalid Signal pre-key message: {error}"))?,
        ),
        "signal-whisper" => libsignal_protocol::CiphertextMessage::SignalMessage(
            libsignal_protocol::SignalMessage::try_from(raw_message.as_slice())
                .map_err(|error| format!("Invalid Signal whisper message: {error}"))?,
        ),
        other => {
            return Err(format!("Unsupported Signal message kind \"{other}\"."));
        }
    };

    let mut csprng = OsRng.unwrap_err();
    let plaintext = block_on(message_decrypt(
        &message,
        &remote_address,
        &local_address,
        &mut store.session_store,
        &mut store.identity_store,
        &mut store.pre_key_store,
        &store.signed_pre_key_store,
        &mut store.kyber_pre_key_store,
        &mut csprng,
    ))
    .map_err(|error| format!("Unable to decrypt the Signal message: {error}"))?;

    Ok(SignalDecryptResponse {
        local_signal_state: store.to_json(
            state.device_id,
            state.next_pre_key_id,
            state.next_signed_pre_key_id,
            state.next_kyber_pre_key_id,
        )?,
        plaintext: String::from_utf8(plaintext)
            .map_err(|error| format!("Signal plaintext was not valid UTF-8: {error}"))?,
    })
}

fn signal_reset_peer(request: SignalResetPeerRequest) -> Result<SignalResetPeerResponse, String> {
    let (mut store, state) = signal_store_from_json(&request.local_signal_state)?;
    let remote_address = SignalAddressRef {
        device_id: DEFAULT_DEVICE_ID,
        name: request.remote_user_id,
    };

    store.session_store.sessions.remove(&remote_address);
    store.identity_store.known_keys.remove(&remote_address);

    Ok(SignalResetPeerResponse {
        local_signal_state: store.to_json(
            state.device_id,
            state.next_pre_key_id,
            state.next_signed_pre_key_id,
            state.next_kyber_pre_key_id,
        )?,
    })
}

fn serialize_mls_storage(provider: &OpenMlsRustCrypto) -> Result<String, String> {
    let values = provider.storage().values.read().unwrap();
    let serializable = values
        .iter()
        .map(|(key, value)| (encode(key), encode(value)))
        .collect::<HashMap<_, _>>();
    serde_json::to_vec(&serializable)
        .map(encode)
        .map_err(|error| format!("Unable to serialize MLS storage: {error}"))
}

fn deserialize_mls_storage(serialized: &str) -> Result<OpenMlsRustCrypto, String> {
    let provider = OpenMlsRustCrypto::default();
    let raw = decode(serialized)?;
    let serializable: HashMap<String, String> = serde_json::from_slice(&raw)
        .map_err(|error| format!("Invalid MLS storage snapshot: {error}"))?;
    let mut values = provider.storage().values.write().unwrap();
    for (key, value) in serializable {
        values.insert(decode(&key)?, decode(&value)?);
    }
    drop(values);
    Ok(provider)
}

fn ciphersuite_label(ciphersuite: Ciphersuite) -> String {
    format!("{ciphersuite:?}")
}

fn default_mls_join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .build()
}

fn deserialize_mls_account(json: &str) -> Result<(MlsAccountState, OpenMlsRustCrypto, CredentialWithKey, SignatureKeyPair), String> {
    let state: MlsAccountState =
        serde_json::from_str(json).map_err(|error| format!("Invalid MLS state: {error}"))?;
    if state.version != MLS_STATE_VERSION {
        return Err(format!("Unsupported MLS state version {}", state.version));
    }
    let provider = deserialize_mls_storage(&state.storage_snapshot)?;
    let credential_with_key: CredentialWithKey =
        serde_json::from_slice(&decode(&state.credential_with_key)?)
            .map_err(|error| format!("Invalid MLS credential payload: {error}"))?;
    let signer: SignatureKeyPair = serde_json::from_slice(&decode(&state.signer)?)
        .map_err(|error| format!("Invalid MLS signer payload: {error}"))?;
    Ok((state, provider, credential_with_key, signer))
}

fn serialize_mls_account(
    provider: &OpenMlsRustCrypto,
    credential_with_key: &CredentialWithKey,
    signer: &SignatureKeyPair,
    ciphersuite: Ciphersuite,
) -> Result<String, String> {
    serde_json::to_string(&MlsAccountState {
        core_version: crate::core_profile_snapshot()["coreVersion"]
            .as_str()
            .unwrap_or("notrus-protocol-core")
            .to_owned(),
        ciphersuite: ciphersuite_label(ciphersuite),
        credential_with_key: encode(
            serde_json::to_vec(credential_with_key)
                .map_err(|error| format!("Unable to serialize MLS credential: {error}"))?,
        ),
        signer: encode(
            serde_json::to_vec(signer)
                .map_err(|error| format!("Unable to serialize MLS signer: {error}"))?,
        ),
        storage_snapshot: serialize_mls_storage(provider)?,
        version: MLS_STATE_VERSION,
    })
    .map_err(|error| format!("Unable to encode MLS state: {error}"))
}

fn generate_mls_key_package(
    provider: &OpenMlsRustCrypto,
    signer: &SignatureKeyPair,
    credential_with_key: &CredentialWithKey,
) -> Result<PublicMlsKeyPackage, String> {
    let bundle = KeyPackage::builder()
        .build(DEFAULT_CIPHERSUITE, provider, signer, credential_with_key.clone())
        .map_err(|error| format!("Unable to build MLS key package: {error}"))?;
    Ok(PublicMlsKeyPackage {
        ciphersuite: ciphersuite_label(DEFAULT_CIPHERSUITE),
        key_package: encode(
            bundle
                .key_package()
                .tls_serialize_detached()
                .map_err(|error| format!("Unable to serialize MLS key package: {error}"))?,
        ),
    })
}

fn create_mls_account(user_id: &str) -> Result<(String, PublicMlsKeyPackage), String> {
    let provider = OpenMlsRustCrypto::default();
    let credential = BasicCredential::new(user_id.as_bytes().to_vec());
    let signer = SignatureKeyPair::new(DEFAULT_CIPHERSUITE.signature_algorithm())
        .map_err(|error| format!("Unable to create MLS signer: {error}"))?;
    signer
        .store(provider.storage())
        .map_err(|error| format!("Unable to store MLS signer: {error}"))?;
    let credential_with_key = CredentialWithKey {
        credential: credential.into(),
        signature_key: signer.to_public_vec().into(),
    };
    let key_package = generate_mls_key_package(&provider, &signer, &credential_with_key)?;
    Ok((
        serialize_mls_account(&provider, &credential_with_key, &signer, DEFAULT_CIPHERSUITE)?,
        key_package,
    ))
}

fn refresh_mls_key_package(request: RefreshMlsKeyPackageRequest) -> Result<RefreshMlsKeyPackageResponse, String> {
    let (_state, provider, credential_with_key, signer) = deserialize_mls_account(&request.mls_state)?;
    let key_package = generate_mls_key_package(&provider, &signer, &credential_with_key)?;
    Ok(RefreshMlsKeyPackageResponse {
        mls_key_package: key_package,
        mls_state: serialize_mls_account(&provider, &credential_with_key, &signer, DEFAULT_CIPHERSUITE)?,
    })
}

fn parse_public_mls_key_package(
    provider: &OpenMlsRustCrypto,
    bundle: &PublicMlsKeyPackage,
) -> Result<KeyPackage, String> {
    let key_package_in = KeyPackageIn::tls_deserialize_exact(&decode(&bundle.key_package)?)
        .map_err(|error| format!("Invalid MLS key package encoding: {error}"))?;
    key_package_in
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .map_err(|error| format!("Invalid MLS key package: {error}"))
}

fn serialize_thread_state(group: &MlsGroup) -> Result<String, String> {
    serde_json::to_string(&MlsThreadState {
        ciphersuite: ciphersuite_label(group.ciphersuite()),
        group_id: encode(group.group_id().as_slice()),
    })
    .map_err(|error| format!("Unable to encode MLS thread state: {error}"))
}

fn load_group(provider: &OpenMlsRustCrypto, thread_state_json: &str) -> Result<(MlsThreadState, MlsGroup), String> {
    let thread_state: MlsThreadState = serde_json::from_str(thread_state_json)
        .map_err(|error| format!("Invalid MLS thread state: {error}"))?;
    let group_id = GroupId::from_slice(&decode(&thread_state.group_id)?);
    let group = MlsGroup::load(provider.storage(), &group_id)
        .map_err(|error| format!("Unable to load MLS group from storage: {error}"))?
        .ok_or_else(|| "MLS group state is missing from storage.".to_owned())?;
    Ok((thread_state, group))
}

fn mls_create_group(request: MlsCreateGroupRequest) -> Result<MlsCreateGroupResponse, String> {
    let (_state, creator_provider, creator_credential, creator_signer) =
        deserialize_mls_account(&request.creator_mls_state)?;
    let group_config = MlsGroupCreateConfig::builder()
        .use_ratchet_tree_extension(true)
        .ciphersuite(DEFAULT_CIPHERSUITE)
        .build();
    let group_id = GroupId::from_slice(request.thread_id.as_bytes());
    let mut group = MlsGroup::new_with_group_id(
        &creator_provider,
        &creator_signer,
        &group_config,
        group_id.clone(),
        creator_credential.clone(),
    )
    .map_err(|error| format!("Unable to create MLS group: {error}"))?;

    let other_participants = request
        .participant_user_ids
        .iter()
        .filter(|user_id| user_id.as_str() != request.creator_user_id.as_str())
        .map(|user_id| {
            request
                .participant_key_packages
                .get(user_id)
                .ok_or_else(|| format!("Missing MLS key package for participant {user_id}."))
                .and_then(|bundle| parse_public_mls_key_package(&creator_provider, bundle))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let (_commit, welcome, _group_info) = group
        .add_members(&creator_provider, &creator_signer, &other_participants)
        .map_err(|error| format!("Unable to add members to the MLS group: {error}"))?;
    group
        .merge_pending_commit(&creator_provider)
        .map_err(|error| format!("Unable to merge the MLS welcome commit: {error}"))?;

    let welcome_bytes = MlsMessageOut::from(welcome)
        .tls_serialize_detached()
        .map_err(|error| format!("Unable to serialize MLS welcome: {error}"))?;
    let welcomes = request
        .participant_user_ids
        .into_iter()
        .filter(|user_id| user_id.as_str() != request.creator_user_id.as_str())
        .map(|to_user_id| MlsWelcomeEnvelope {
            to_user_id,
            welcome: encode(&welcome_bytes),
        })
        .collect::<Vec<_>>();

    Ok(MlsCreateGroupResponse {
        creator_mls_state: serialize_mls_account(
            &creator_provider,
            &creator_credential,
            &creator_signer,
            group.ciphersuite(),
        )?,
        thread_bootstrap: MlsThreadBootstrap {
            ciphersuite: ciphersuite_label(group.ciphersuite()),
            group_id: encode(group_id.as_slice()),
            welcomes,
        },
        thread_state: serialize_thread_state(&group)?,
    })
}

fn mls_join_group(request: MlsJoinGroupRequest) -> Result<MlsJoinGroupResponse, String> {
    let (_state, provider, credential_with_key, signer) =
        deserialize_mls_account(&request.local_mls_state)?;
    let welcome = request
        .thread_bootstrap
        .welcomes
        .iter()
        .find(|welcome| welcome.to_user_id == request.local_user_id)
        .ok_or_else(|| "This MLS thread does not include a welcome for the local user.".to_owned())?;
    let welcome_in = MlsMessageIn::tls_deserialize_exact(&decode(&welcome.welcome)?)
        .map_err(|error| format!("Invalid MLS welcome encoding: {error}"))?;
    let welcome_message = match welcome_in.extract() {
        MlsMessageBodyIn::Welcome(welcome_message) => welcome_message,
        _ => return Err("MLS bootstrap payload was not a Welcome message.".to_owned()),
    };
    let staged = StagedWelcome::new_from_welcome(
        &provider,
        &default_mls_join_config(),
        welcome_message,
        None,
    )
    .map_err(|error| format!("Unable to construct staged MLS welcome: {error}"))?;
    let group = staged
        .into_group(&provider)
        .map_err(|error| format!("Unable to join MLS group: {error}"))?;

    Ok(MlsJoinGroupResponse {
        local_mls_state: serialize_mls_account(
            &provider,
            &credential_with_key,
            &signer,
            group.ciphersuite(),
        )?,
        thread_state: serialize_thread_state(&group)?,
    })
}

fn mls_encrypt_message(request: MlsEncryptMessageRequest) -> Result<MlsEncryptMessageResponse, String> {
    let (_state, provider, credential_with_key, signer) =
        deserialize_mls_account(&request.local_mls_state)?;
    let (_thread_state, mut group) = load_group(&provider, &request.thread_state)?;
    let message = group
        .create_message(&provider, &signer, request.plaintext.as_bytes())
        .map_err(|error| format!("Unable to create MLS application message: {error}"))?;

    Ok(MlsEncryptMessageResponse {
        local_mls_state: serialize_mls_account(
            &provider,
            &credential_with_key,
            &signer,
            group.ciphersuite(),
        )?,
        thread_state: serialize_thread_state(&group)?,
        wire_message: encode(
            message
                .tls_serialize_detached()
                .map_err(|error| format!("Unable to serialize MLS application message: {error}"))?,
        ),
    })
}

fn mls_process_message(request: MlsProcessMessageRequest) -> Result<MlsProcessMessageResponse, String> {
    let (_state, provider, credential_with_key, signer) =
        deserialize_mls_account(&request.local_mls_state)?;
    let (_thread_state, mut group) = load_group(&provider, &request.thread_state)?;
    let message = MlsMessageIn::tls_deserialize_exact(&decode(&request.wire_message)?)
        .map_err(|error| format!("Invalid MLS wire message: {error}"))?;
    let processed = group
        .process_message(
            &provider,
            message
                .try_into_protocol_message()
                .map_err(|error| format!("MLS wire message was not a protocol message: {error}"))?,
        )
        .map_err(|error| format!("Unable to process the MLS message: {error}"))?;

    let plaintext = match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(application) => String::from_utf8(application.into_bytes())
            .map_err(|error| format!("MLS application payload was not valid UTF-8: {error}"))?,
        ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
            group
                .merge_staged_commit(&provider, *staged_commit)
                .map_err(|error| format!("Unable to merge the staged MLS commit: {error}"))?;
            "[system] Group state updated.".to_owned()
        }
        other => {
            return Err(format!("Unsupported MLS processed message content: {other:?}"));
        }
    };

    Ok(MlsProcessMessageResponse {
        local_mls_state: serialize_mls_account(
            &provider,
            &credential_with_key,
            &signer,
            group.ciphersuite(),
        )?,
        plaintext,
        thread_state: serialize_thread_state(&group)?,
    })
}

pub fn handle_request(request: BridgeRequest) -> Result<serde_json::Value, String> {
    std::panic::catch_unwind(move || match request {
        BridgeRequest::ProfileSnapshot => Ok(crate::core_profile_snapshot()),
        BridgeRequest::CreateIdentity(request) => {
            let signal_identity = create_signal_identity_material()?;
            let (mls_state, mls_key_package) = create_mls_account(&request.thread_user_id)?;
            Ok(serde_json::to_value(CreateIdentityResponse {
                fingerprint: identity_fingerprint(
                    &decode(&signal_identity.bundle.identity_key)?,
                ),
                mls_key_package,
                mls_state,
                signal_bundle: signal_identity.bundle,
                signal_state: signal_identity.store.to_json(
                    signal_identity.device_id,
                    signal_identity.next_pre_key_id,
                    signal_identity.next_signed_pre_key_id,
                    signal_identity.next_kyber_pre_key_id,
                )?,
            })
            .map_err(|error| format!("Unable to encode create-identity response: {error}"))?)
        }
        BridgeRequest::RefreshMlsKeyPackage(request) => Ok(
            serde_json::to_value(refresh_mls_key_package(request)?)
                .map_err(|error| format!("Unable to encode MLS key-package refresh response: {error}"))?,
        ),
        BridgeRequest::RefreshSignalBundle(request) => Ok(
            serde_json::to_value(refresh_signal_bundle(request)?)
                .map_err(|error| format!("Unable to encode signal bundle refresh response: {error}"))?,
        ),
        BridgeRequest::SignalEncrypt(request) => Ok(
            serde_json::to_value(signal_encrypt(request)?)
                .map_err(|error| format!("Unable to encode signal encrypt response: {error}"))?,
        ),
        BridgeRequest::SignalDecrypt(request) => Ok(
            serde_json::to_value(signal_decrypt(request)?)
                .map_err(|error| format!("Unable to encode signal decrypt response: {error}"))?,
        ),
        BridgeRequest::SignalResetPeer(request) => Ok(
            serde_json::to_value(signal_reset_peer(request)?)
                .map_err(|error| format!("Unable to encode signal reset-peer response: {error}"))?,
        ),
        BridgeRequest::MlsCreateGroup(request) => Ok(
            serde_json::to_value(mls_create_group(request)?)
                .map_err(|error| format!("Unable to encode MLS create-group response: {error}"))?,
        ),
        BridgeRequest::MlsJoinGroup(request) => Ok(
            serde_json::to_value(mls_join_group(request)?)
                .map_err(|error| format!("Unable to encode MLS join-group response: {error}"))?,
        ),
        BridgeRequest::MlsEncryptMessage(request) => Ok(
            serde_json::to_value(mls_encrypt_message(request)?)
                .map_err(|error| format!("Unable to encode MLS encrypt response: {error}"))?,
        ),
        BridgeRequest::MlsProcessMessage(request) => Ok(
            serde_json::to_value(mls_process_message(request)?)
                .map_err(|error| format!("Unable to encode MLS process response: {error}"))?,
        ),
    })
    .map_err(|_| "Protocol core panicked while handling untrusted input.".to_owned())?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_identity_emits_both_standard_stacks() {
        let response = handle_request(BridgeRequest::CreateIdentity(CreateIdentityRequest {
            display_name: "Alice".to_owned(),
            thread_user_id: "alice-user".to_owned(),
            username: "alice".to_owned(),
        }))
        .expect("identity creation should succeed");

        let decoded: CreateIdentityResponse =
            serde_json::from_value(response).expect("response should decode");
        assert!(!decoded.fingerprint.is_empty());
        assert!(!decoded.signal_state.is_empty());
        assert!(!decoded.mls_state.is_empty());
        assert!(!decoded.signal_bundle.identity_key.is_empty());
        assert!(!decoded.mls_key_package.key_package.is_empty());
    }

    #[test]
    fn signal_direct_round_trip_works_through_serialized_state() {
        let alice: CreateIdentityResponse = serde_json::from_value(
            handle_request(BridgeRequest::CreateIdentity(CreateIdentityRequest {
                display_name: "Alice".to_owned(),
                thread_user_id: "alice-user".to_owned(),
                username: "alice".to_owned(),
            }))
            .expect("alice identity should succeed"),
        )
        .expect("alice response should decode");
        let bob: CreateIdentityResponse = serde_json::from_value(
            handle_request(BridgeRequest::CreateIdentity(CreateIdentityRequest {
                display_name: "Bob".to_owned(),
                thread_user_id: "bob-user".to_owned(),
                username: "bob".to_owned(),
            }))
            .expect("bob identity should succeed"),
        )
        .expect("bob response should decode");

        let alice_send: SignalEncryptResponse = serde_json::from_value(
            handle_request(BridgeRequest::SignalEncrypt(SignalEncryptRequest {
                local_signal_state: alice.signal_state,
                local_user_id: "alice-user".to_owned(),
                plaintext: "hello from signal".to_owned(),
                remote_bundle: bob.signal_bundle.clone(),
                remote_user_id: "bob-user".to_owned(),
            }))
            .expect("signal encrypt should succeed"),
        )
        .expect("encrypt response should decode");

        let bob_receive: SignalDecryptResponse = serde_json::from_value(
            handle_request(BridgeRequest::SignalDecrypt(SignalDecryptRequest {
                local_signal_state: bob.signal_state,
                local_user_id: "bob-user".to_owned(),
                message_kind: alice_send.message_kind.clone(),
                remote_user_id: "alice-user".to_owned(),
                wire_message: alice_send.wire_message.clone(),
            }))
            .expect("signal decrypt should succeed"),
        )
        .expect("decrypt response should decode");

        assert_eq!(bob_receive.plaintext, "hello from signal");

        let bob_reply: SignalEncryptResponse = serde_json::from_value(
            handle_request(BridgeRequest::SignalEncrypt(SignalEncryptRequest {
                local_signal_state: bob_receive.local_signal_state,
                local_user_id: "bob-user".to_owned(),
                plaintext: "reply from signal".to_owned(),
                remote_bundle: alice.signal_bundle,
                remote_user_id: "alice-user".to_owned(),
            }))
            .expect("reply encrypt should succeed"),
        )
        .expect("reply encrypt response should decode");

        let alice_receive: SignalDecryptResponse = serde_json::from_value(
            handle_request(BridgeRequest::SignalDecrypt(SignalDecryptRequest {
                local_signal_state: alice_send.local_signal_state,
                local_user_id: "alice-user".to_owned(),
                message_kind: bob_reply.message_kind,
                remote_user_id: "bob-user".to_owned(),
                wire_message: bob_reply.wire_message,
            }))
            .expect("reply decrypt should succeed"),
        )
        .expect("reply decrypt response should decode");

        assert_eq!(alice_receive.plaintext, "reply from signal");
    }

    #[test]
    fn mls_group_round_trip_works_through_serialized_state() {
        let alice: CreateIdentityResponse = serde_json::from_value(
            handle_request(BridgeRequest::CreateIdentity(CreateIdentityRequest {
                display_name: "Alice".to_owned(),
                thread_user_id: "alice-user".to_owned(),
                username: "alice".to_owned(),
            }))
            .expect("alice identity should succeed"),
        )
        .expect("alice response should decode");
        let bob: CreateIdentityResponse = serde_json::from_value(
            handle_request(BridgeRequest::CreateIdentity(CreateIdentityRequest {
                display_name: "Bob".to_owned(),
                thread_user_id: "bob-user".to_owned(),
                username: "bob".to_owned(),
            }))
            .expect("bob identity should succeed"),
        )
        .expect("bob response should decode");
        let charlie: CreateIdentityResponse = serde_json::from_value(
            handle_request(BridgeRequest::CreateIdentity(CreateIdentityRequest {
                display_name: "Charlie".to_owned(),
                thread_user_id: "charlie-user".to_owned(),
                username: "charlie".to_owned(),
            }))
            .expect("charlie identity should succeed"),
        )
        .expect("charlie response should decode");

        let create_group: MlsCreateGroupResponse = serde_json::from_value(
            handle_request(BridgeRequest::MlsCreateGroup(MlsCreateGroupRequest {
                creator_mls_state: alice.mls_state,
                creator_user_id: "alice-user".to_owned(),
                participant_key_packages: HashMap::from([
                    ("bob-user".to_owned(), bob.mls_key_package.clone()),
                    ("charlie-user".to_owned(), charlie.mls_key_package.clone()),
                ]),
                participant_user_ids: vec![
                    "alice-user".to_owned(),
                    "bob-user".to_owned(),
                    "charlie-user".to_owned(),
                ],
                thread_id: "mls-thread-1".to_owned(),
            }))
            .expect("mls group creation should succeed"),
        )
        .expect("group response should decode");

        let bob_join: MlsJoinGroupResponse = serde_json::from_value(
            handle_request(BridgeRequest::MlsJoinGroup(MlsJoinGroupRequest {
                local_mls_state: bob.mls_state,
                local_user_id: "bob-user".to_owned(),
                thread_bootstrap: create_group.thread_bootstrap.clone(),
            }))
            .expect("bob join should succeed"),
        )
        .expect("bob join response should decode");

        let charlie_join: MlsJoinGroupResponse = serde_json::from_value(
            handle_request(BridgeRequest::MlsJoinGroup(MlsJoinGroupRequest {
                local_mls_state: charlie.mls_state,
                local_user_id: "charlie-user".to_owned(),
                thread_bootstrap: create_group.thread_bootstrap,
            }))
            .expect("charlie join should succeed"),
        )
        .expect("charlie join response should decode");

        let alice_send: MlsEncryptMessageResponse = serde_json::from_value(
            handle_request(BridgeRequest::MlsEncryptMessage(MlsEncryptMessageRequest {
                local_mls_state: create_group.creator_mls_state,
                plaintext: "hello from mls".to_owned(),
                thread_state: create_group.thread_state,
            }))
            .expect("alice mls send should succeed"),
        )
        .expect("alice send response should decode");

        let bob_receive: MlsProcessMessageResponse = serde_json::from_value(
            handle_request(BridgeRequest::MlsProcessMessage(MlsProcessMessageRequest {
                local_mls_state: bob_join.local_mls_state,
                thread_state: bob_join.thread_state,
                wire_message: alice_send.wire_message.clone(),
            }))
            .expect("bob should process mls message"),
        )
        .expect("bob process response should decode");

        let charlie_receive: MlsProcessMessageResponse = serde_json::from_value(
            handle_request(BridgeRequest::MlsProcessMessage(MlsProcessMessageRequest {
                local_mls_state: charlie_join.local_mls_state,
                thread_state: charlie_join.thread_state,
                wire_message: alice_send.wire_message,
            }))
            .expect("charlie should process mls message"),
        )
        .expect("charlie process response should decode");

        assert_eq!(bob_receive.plaintext, "hello from mls");
        assert_eq!(charlie_receive.plaintext, "hello from mls");
    }
}
