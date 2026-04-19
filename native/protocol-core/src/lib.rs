pub mod bridge;

use libsignal_protocol::{IdentityKeyPair, InMemSignalProtocolStore};
use openmls::prelude::Ciphersuite;
use openmls_rust_crypto::OpenMlsRustCrypto;
use std::ffi::{CString, c_char};

#[cfg(test)]
use openmls_basic_credential::SignatureKeyPair;
use rand_core::OsRng;
use rand_core::TryRngCore as _;

#[cfg(test)]
use libsignal_protocol::{
    CiphertextMessageType, DeviceId, GenericSignedPreKey, IdentityKeyStore, KeyPair,
    KyberPreKeyRecord, KyberPreKeyStore, PreKeyBundle, PreKeyRecord, PreKeyStore,
    ProtocolAddress, SignedPreKeyRecord, SignedPreKeyStore, Timestamp, kem, message_decrypt,
    message_encrypt, process_prekey_bundle,
};

#[cfg(test)]
use std::time::SystemTime;

#[cfg(test)]
use futures::executor::block_on;

const CORE_VERSION: &str = concat!("notrus-protocol-core/", env!("CARGO_PKG_VERSION"));
const CORE_VERSION_C: &[u8] = b"notrus-protocol-core/0.1.0\0";
const MESSAGE_ENCODING: &str = "base64-standard";
const MESSAGE_WRAPPER: &str = "json-utf8";
const MLS_BASIC_CREDENTIAL_VERSION: &str = "0.5.0";
const MLS_CIPHERSUITE_LABEL: &str = "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519";
const MLS_LABEL: &str = "MLS RFC 9420 (OpenMLS)";
const MLS_LABEL_C: &[u8] = b"MLS RFC 9420 (OpenMLS)\0";
const OPENMLS_RUST_CRYPTO_VERSION: &str = "0.5.1";
const OPENMLS_VERSION: &str = "0.8.1";
const SIGNAL_LABEL: &str = "Signal Protocol (official libsignal)";
const SIGNAL_LABEL_C: &[u8] = b"Signal Protocol (official libsignal)\0";
const SIGNAL_UPSTREAM_REV: &str = "8418be45dba3ebc17127b5c6b76ce02886350524";
const TRANSPORT_TLS_MIN_VERSION: &str = "1.3";

#[repr(C)]
pub struct CoreProfile {
    pub core_version: *const c_char,
    pub signal_label: *const c_char,
    pub mls_label: *const c_char,
    pub mls_mti_ciphersuite_code: u16,
}

#[no_mangle]
pub extern "C" fn notrus_protocol_core_profile() -> CoreProfile {
    let _provider = OpenMlsRustCrypto::default();

    CoreProfile {
        core_version: CORE_VERSION_C.as_ptr().cast(),
        signal_label: SIGNAL_LABEL_C.as_ptr().cast(),
        mls_label: MLS_LABEL_C.as_ptr().cast(),
        mls_mti_ciphersuite_code: Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 as u16,
    }
}

#[no_mangle]
pub extern "C" fn notrus_protocol_core_snapshot_json() -> *mut c_char {
    match CString::new(standards_core_ready_snapshot().to_string()) {
        Ok(value) => value.into_raw(),
        Err(_error) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn notrus_protocol_core_free_string(value: *mut c_char) {
    if value.is_null() {
        return;
    }

    unsafe {
        drop(CString::from_raw(value));
    }
}

pub fn core_profile_snapshot() -> serde_json::Value {
    let _provider = OpenMlsRustCrypto::default();

    serde_json::json!({
        "coreVersion": CORE_VERSION,
        "signal": {
            "backend": "libsignal-protocol",
            "label": SIGNAL_LABEL,
            "messageEncoding": MESSAGE_ENCODING,
            "messageWrapper": MESSAGE_WRAPPER,
            "upstreamRev": SIGNAL_UPSTREAM_REV
        },
        "mls": {
            "label": MLS_LABEL,
            "backend": "openmls",
            "basicCredentialVersion": MLS_BASIC_CREDENTIAL_VERSION,
            "ciphersuite": MLS_CIPHERSUITE_LABEL,
            "openmlsRustCryptoVersion": OPENMLS_RUST_CRYPTO_VERSION,
            "openmlsVersion": OPENMLS_VERSION,
            "rfc": 9420
        },
        "transport": {
            "minimumTlsVersion": TRANSPORT_TLS_MIN_VERSION,
            "role": "transport-only"
        }
    })
}

pub fn mls_provider_ready() -> bool {
    let _provider = OpenMlsRustCrypto::default();
    true
}

pub fn signal_provider_ready() -> bool {
    let mut csprng = OsRng.unwrap_err();
    let identity = IdentityKeyPair::generate(&mut csprng);
    InMemSignalProtocolStore::new(identity, 7).is_ok()
}

pub fn standards_core_ready_snapshot() -> serde_json::Value {
    serde_json::json!({
        "coreVersion": CORE_VERSION,
        "signalReady": signal_provider_ready(),
        "mlsReady": mls_provider_ready(),
        "messageEncoding": MESSAGE_ENCODING,
        "messageWrapper": MESSAGE_WRAPPER,
        "minimumTlsVersion": TRANSPORT_TLS_MIN_VERSION,
        "mlsBasicCredentialVersion": MLS_BASIC_CREDENTIAL_VERSION,
        "mlsCiphersuite": MLS_CIPHERSUITE_LABEL,
        "openmlsRustCryptoVersion": OPENMLS_RUST_CRYPTO_VERSION,
        "openmlsVersion": OPENMLS_VERSION,
        "signalUpstreamRev": SIGNAL_UPSTREAM_REV,
        "mlsRfc": 9420
    })
}

#[cfg(test)]
fn create_signal_store(registration_id: u32) -> InMemSignalProtocolStore {
    let mut csprng = OsRng.unwrap_err();
    let identity = IdentityKeyPair::generate(&mut csprng);
    InMemSignalProtocolStore::new(identity, registration_id).expect("should create signal store")
}

#[cfg(test)]
fn create_signal_bundle(
    store: &mut InMemSignalProtocolStore,
    device_id: DeviceId,
) -> PreKeyBundle {
    let mut csprng = OsRng.unwrap_err();

    let pre_key_id = 1u32;
    let signed_pre_key_id = 1u32;
    let kyber_pre_key_id = 1u32;

    let pre_key_pair = KeyPair::generate(&mut csprng);
    let signed_pre_key_pair = KeyPair::generate(&mut csprng);

    let identity_key_pair = block_on(store.get_identity_key_pair()).expect("identity should load");
    let signed_pre_key_signature = identity_key_pair
        .private_key()
        .calculate_signature(&signed_pre_key_pair.public_key.serialize(), &mut csprng)
        .expect("should sign signed pre-key");
    let kyber_pre_key_record = KyberPreKeyRecord::generate(
        kem::KeyType::Kyber1024,
        kyber_pre_key_id.into(),
        identity_key_pair.private_key(),
    )
    .expect("should generate kyber pre-key");

    block_on(store.save_pre_key(
        pre_key_id.into(),
        &PreKeyRecord::new(pre_key_id.into(), &pre_key_pair),
    ))
    .expect("pre-key save should succeed");

    block_on(store.save_signed_pre_key(
        signed_pre_key_id.into(),
        &SignedPreKeyRecord::new(
            signed_pre_key_id.into(),
            Timestamp::from_epoch_millis(42),
            &signed_pre_key_pair,
            &signed_pre_key_signature,
        ),
    ))
    .expect("signed pre-key save should succeed");

    block_on(store.save_kyber_pre_key(
        kyber_pre_key_id.into(),
        &kyber_pre_key_record,
    ))
    .expect("kyber pre-key save should succeed");

    PreKeyBundle::new(
        block_on(store.get_local_registration_id()).expect("registration id should load"),
        device_id,
        Some((pre_key_id.into(), pre_key_pair.public_key)),
        signed_pre_key_id.into(),
        signed_pre_key_pair.public_key,
        signed_pre_key_signature.to_vec(),
        kyber_pre_key_id.into(),
        kyber_pre_key_record.public_key().expect("kyber public key should load"),
        kyber_pre_key_record.signature().expect("kyber signature should load"),
        *identity_key_pair.identity_key(),
    )
    .expect("bundle creation should succeed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::{
        handle_request, BridgeRequest, MlsJoinGroupRequest, MlsProcessMessageRequest,
        MlsThreadBootstrap, MlsWelcomeEnvelope, PublicSignalBundle, SignalDecryptRequest,
        SignalEncryptRequest,
    };
    use std::{fs, path::PathBuf};

    fn test_vectors_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test-vectors")
    }

    fn signal_bundle_from_fixture(value: &serde_json::Value) -> PublicSignalBundle {
        PublicSignalBundle {
            device_id: value["deviceId"]
                .as_u64()
                .expect("fixture signal bundle device id should exist")
                as u32,
            identity_key: value["identityKey"]
                .as_str()
                .expect("fixture signal bundle identity key should exist")
                .to_owned(),
            kyber_pre_key_id: value["kyberPreKeyId"]
                .as_u64()
                .expect("fixture signal bundle kyber pre-key id should exist")
                as u32,
            kyber_pre_key_public: value["kyberPreKeyPublic"]
                .as_str()
                .expect("fixture signal bundle kyber public key should exist")
                .to_owned(),
            kyber_pre_key_signature: value["kyberPreKeySignature"]
                .as_str()
                .expect("fixture signal bundle kyber signature should exist")
                .to_owned(),
            pre_key_id: value["preKeyId"]
                .as_u64()
                .expect("fixture signal bundle pre-key id should exist")
                as u32,
            pre_key_public: value["preKeyPublic"]
                .as_str()
                .expect("fixture signal bundle pre-key public key should exist")
                .to_owned(),
            registration_id: value["registrationId"]
                .as_u64()
                .expect("fixture signal bundle registration id should exist")
                as u32,
            signed_pre_key_id: value["signedPreKeyId"]
                .as_u64()
                .expect("fixture signal bundle signed pre-key id should exist")
                as u32,
            signed_pre_key_public: value["signedPreKeyPublic"]
                .as_str()
                .expect("fixture signal bundle signed pre-key public key should exist")
                .to_owned(),
            signed_pre_key_signature: value["signedPreKeySignature"]
                .as_str()
                .expect("fixture signal bundle signed pre-key signature should exist")
                .to_owned(),
        }
    }

    fn assert_signal_state_semantics(actual_json: &str, expected_json: &str) {
        let actual: serde_json::Value =
            serde_json::from_str(actual_json).expect("actual signal state should decode");
        let expected: serde_json::Value =
            serde_json::from_str(expected_json).expect("expected signal state should decode");

        for key in [
            "core_version",
            "device_id",
            "identity_key_pair",
            "known_identities",
            "kyber_pre_key_usage",
            "kyber_pre_keys",
            "next_kyber_pre_key_id",
            "next_pre_key_id",
            "next_signed_pre_key_id",
            "pre_keys",
            "registration_id",
            "signed_pre_keys",
            "version",
        ] {
            assert_eq!(actual[key], expected[key], "stable signal state field {key} should match");
        }

        let actual_sessions = actual["sessions"]
            .as_array()
            .expect("actual signal sessions should exist");
        let expected_sessions = expected["sessions"]
            .as_array()
            .expect("expected signal sessions should exist");
        assert_eq!(actual_sessions.len(), expected_sessions.len());
        for (actual_session, expected_session) in actual_sessions.iter().zip(expected_sessions.iter()) {
            assert_eq!(actual_session["address"], expected_session["address"]);
            let actual_serialized = actual_session["session"]
                .as_str()
                .expect("actual signal session should be a string");
            let expected_serialized = expected_session["session"]
                .as_str()
                .expect("expected signal session should be a string");
            assert!(!actual_serialized.is_empty());
            assert_eq!(actual_serialized.len(), expected_serialized.len());
        }
    }

    #[test]
    fn exposes_openmls_profile_snapshot() {
        let snapshot = core_profile_snapshot();
        assert_eq!(snapshot["signal"]["backend"], "libsignal-protocol");
        assert_eq!(snapshot["signal"]["messageEncoding"], MESSAGE_ENCODING);
        assert_eq!(snapshot["signal"]["messageWrapper"], MESSAGE_WRAPPER);
        assert_eq!(snapshot["mls"]["backend"], "openmls");
        assert_eq!(snapshot["mls"]["basicCredentialVersion"], MLS_BASIC_CREDENTIAL_VERSION);
        assert_eq!(snapshot["mls"]["ciphersuite"], MLS_CIPHERSUITE_LABEL);
        assert_eq!(snapshot["mls"]["openmlsRustCryptoVersion"], OPENMLS_RUST_CRYPTO_VERSION);
        assert_eq!(snapshot["mls"]["openmlsVersion"], OPENMLS_VERSION);
        assert_eq!(snapshot["mls"]["rfc"], 9420);
        assert_eq!(snapshot["transport"]["minimumTlsVersion"], TRANSPORT_TLS_MIN_VERSION);
        assert_eq!(snapshot["transport"]["role"], "transport-only");
    }

    #[test]
    fn standards_snapshot_reports_both_stacks_ready() {
        let snapshot = standards_core_ready_snapshot();
        assert_eq!(snapshot["signalReady"], true);
        assert_eq!(snapshot["mlsReady"], true);
        assert_eq!(snapshot["messageEncoding"], MESSAGE_ENCODING);
        assert_eq!(snapshot["messageWrapper"], MESSAGE_WRAPPER);
        assert_eq!(snapshot["minimumTlsVersion"], TRANSPORT_TLS_MIN_VERSION);
        assert_eq!(snapshot["mlsBasicCredentialVersion"], MLS_BASIC_CREDENTIAL_VERSION);
        assert_eq!(snapshot["mlsCiphersuite"], MLS_CIPHERSUITE_LABEL);
        assert_eq!(snapshot["openmlsRustCryptoVersion"], OPENMLS_RUST_CRYPTO_VERSION);
        assert_eq!(snapshot["openmlsVersion"], OPENMLS_VERSION);
        assert_eq!(snapshot["mlsRfc"], 9420);
    }

    #[test]
    fn provider_boots_and_signature_keys_can_be_generated() {
        let _provider = OpenMlsRustCrypto::default();
        let signer = SignatureKeyPair::new(
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519.signature_algorithm(),
        )
        .expect("should generate MLS signing keys");
        assert!(!signer.public().is_empty());
    }

    #[test]
    fn official_signal_prekey_session_round_trip_works() {
        let alice_address = ProtocolAddress::new("alice".to_owned(), DeviceId::new(1).unwrap());
        let bob_address = ProtocolAddress::new("bob".to_owned(), DeviceId::new(1).unwrap());

        let mut alice_store = create_signal_store(11);
        let mut bob_store = create_signal_store(22);
        let bob_bundle = create_signal_bundle(&mut bob_store, DeviceId::new(1).unwrap());

        let mut csprng = OsRng.unwrap_err();

        block_on(process_prekey_bundle(
            &bob_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            &bob_bundle,
            SystemTime::now(),
            &mut csprng,
        ))
        .expect("initiator session setup should succeed");

        let outgoing = block_on(message_encrypt(
            b"hello from libsignal",
            &bob_address,
            &alice_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            SystemTime::now(),
            &mut csprng,
        ))
        .expect("first message should encrypt");

        assert_eq!(outgoing.message_type(), CiphertextMessageType::PreKey);

        let decrypted = block_on(message_decrypt(
            &outgoing,
            &alice_address,
            &bob_address,
            &mut bob_store.session_store,
            &mut bob_store.identity_store,
            &mut bob_store.pre_key_store,
            &bob_store.signed_pre_key_store,
            &mut bob_store.kyber_pre_key_store,
            &mut csprng,
        ))
        .expect("recipient should decrypt pre-key message");

        assert_eq!(decrypted, b"hello from libsignal");

        let reply = block_on(message_encrypt(
            b"reply from libsignal",
            &alice_address,
            &bob_address,
            &mut bob_store.session_store,
            &mut bob_store.identity_store,
            SystemTime::now(),
            &mut csprng,
        ))
        .expect("reply should encrypt");

        assert_eq!(reply.message_type(), CiphertextMessageType::Whisper);

        let decrypted_reply = block_on(message_decrypt(
            &reply,
            &bob_address,
            &alice_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            &mut alice_store.pre_key_store,
            &alice_store.signed_pre_key_store,
            &mut alice_store.kyber_pre_key_store,
            &mut csprng,
        ))
        .expect("initiator should decrypt reply");

        assert_eq!(decrypted_reply, b"reply from libsignal");
    }

    #[test]
    fn signal_vector_fixture_replays() {
        let fixture_path = test_vectors_dir().join("signal-direct-v1.json");
        let fixture_raw = fs::read_to_string(&fixture_path).expect("signal fixture should load");
        let fixture: serde_json::Value =
            serde_json::from_str(&fixture_raw).expect("signal fixture should decode");

        assert_eq!(fixture["protocol"], "signal-pqxdh-double-ratchet-v1");
        assert_eq!(fixture["messageEncoding"], MESSAGE_ENCODING);
        assert_eq!(fixture["transport"]["minimumTlsVersion"], TRANSPORT_TLS_MIN_VERSION);

        let bob_receive = handle_request(BridgeRequest::SignalDecrypt(SignalDecryptRequest {
            local_signal_state: fixture["actors"]["bob"]["initialState"]
                .as_str()
                .expect("bob state should exist")
                .to_owned(),
            local_user_id: fixture["actors"]["bob"]["userId"]
                .as_str()
                .expect("bob user should exist")
                .to_owned(),
            message_kind: fixture["messages"][0]["messageKind"]
                .as_str()
                .expect("signal message kind should exist")
                .to_owned(),
            remote_user_id: fixture["actors"]["alice"]["userId"]
                .as_str()
                .expect("alice user should exist")
                .to_owned(),
            wire_message: fixture["messages"][0]["wireMessage"]
                .as_str()
                .expect("signal wire should exist")
                .to_owned(),
        }))
        .expect("bob should decrypt the signal vector");
        assert_eq!(
            bob_receive["plaintext"],
            fixture["messages"][0]["expectedPlaintext"]
        );

        assert_signal_state_semantics(
            bob_receive["local_signal_state"]
                .as_str()
                .expect("bob receive state should exist"),
            fixture["actors"]["bob"]["stateAfterFirstReceive"]
                .as_str()
                .expect("expected bob receive state should exist"),
        );

        let bob_live_reply = handle_request(BridgeRequest::SignalEncrypt(SignalEncryptRequest {
            local_signal_state: bob_receive["local_signal_state"]
                .as_str()
                .expect("bob receive state should exist")
                .to_owned(),
            local_user_id: fixture["actors"]["bob"]["userId"]
                .as_str()
                .expect("bob user should exist")
                .to_owned(),
            plaintext: "fresh replay response".to_owned(),
            remote_bundle: signal_bundle_from_fixture(&fixture["actors"]["alice"]["bundle"]),
            remote_user_id: fixture["actors"]["alice"]["userId"]
                .as_str()
                .expect("alice user should exist")
                .to_owned(),
        }))
        .expect("bob should re-encrypt from the replayed signal state");

        let alice_receive = handle_request(BridgeRequest::SignalDecrypt(SignalDecryptRequest {
            local_signal_state: fixture["actors"]["alice"]["stateAfterFirstSend"]
                .as_str()
                .expect("alice post-send state should exist")
                .to_owned(),
            local_user_id: fixture["actors"]["alice"]["userId"]
                .as_str()
                .expect("alice user should exist")
                .to_owned(),
            message_kind: fixture["messages"][1]["messageKind"]
                .as_str()
                .expect("reply message kind should exist")
                .to_owned(),
            remote_user_id: fixture["actors"]["bob"]["userId"]
                .as_str()
                .expect("bob user should exist")
                .to_owned(),
            wire_message: fixture["messages"][1]["wireMessage"]
                .as_str()
                .expect("reply wire should exist")
                .to_owned(),
        }))
        .expect("alice should decrypt the signal reply vector");
        assert_eq!(
            alice_receive["plaintext"],
            fixture["messages"][1]["expectedPlaintext"]
        );

        let alice_live_receive = handle_request(BridgeRequest::SignalDecrypt(SignalDecryptRequest {
            local_signal_state: fixture["actors"]["alice"]["stateAfterFirstSend"]
                .as_str()
                .expect("alice post-send state should exist")
                .to_owned(),
            local_user_id: fixture["actors"]["alice"]["userId"]
                .as_str()
                .expect("alice user should exist")
                .to_owned(),
            message_kind: bob_live_reply["message_kind"]
                .as_str()
                .expect("live reply message kind should exist")
                .to_owned(),
            remote_user_id: fixture["actors"]["bob"]["userId"]
                .as_str()
                .expect("bob user should exist")
                .to_owned(),
            wire_message: bob_live_reply["wire_message"]
                .as_str()
                .expect("live reply wire should exist")
                .to_owned(),
        }))
        .expect("alice should decrypt a fresh reply produced from the replayed signal state");
        assert_eq!(alice_live_receive["plaintext"], "fresh replay response");
    }

    #[test]
    fn mls_vector_fixture_replays() {
        let fixture_path = test_vectors_dir().join("mls-group-v1.json");
        let fixture_raw = fs::read_to_string(&fixture_path).expect("mls fixture should load");
        let fixture: serde_json::Value =
            serde_json::from_str(&fixture_raw).expect("mls fixture should decode");

        assert_eq!(fixture["protocol"], "mls-rfc9420-v1");
        assert_eq!(fixture["ciphersuite"], MLS_CIPHERSUITE_LABEL);
        assert_eq!(fixture["transport"]["minimumTlsVersion"], TRANSPORT_TLS_MIN_VERSION);

        let thread_bootstrap = MlsThreadBootstrap {
            ciphersuite: fixture["threadBootstrap"]["ciphersuite"]
                .as_str()
                .expect("bootstrap ciphersuite should exist")
                .to_owned(),
            group_id: fixture["threadBootstrap"]["groupId"]
                .as_str()
                .expect("bootstrap group id should exist")
                .to_owned(),
            welcomes: fixture["threadBootstrap"]["welcomes"]
                .as_array()
                .expect("bootstrap welcomes should exist")
                .iter()
                .map(|welcome| MlsWelcomeEnvelope {
                    to_user_id: welcome["toUserId"]
                        .as_str()
                        .expect("welcome user should exist")
                        .to_owned(),
                    welcome: welcome["welcome"]
                        .as_str()
                        .expect("welcome payload should exist")
                        .to_owned(),
                })
                .collect(),
        };

        let bob_join = handle_request(BridgeRequest::MlsJoinGroup(MlsJoinGroupRequest {
            local_mls_state: fixture["actors"]["bob"]["initialState"]
                .as_str()
                .expect("bob mls state should exist")
                .to_owned(),
            local_user_id: fixture["actors"]["bob"]["userId"]
                .as_str()
                .expect("bob user should exist")
                .to_owned(),
            thread_bootstrap: thread_bootstrap.clone(),
        }))
        .expect("bob should join the MLS group vector");
        assert_eq!(
            bob_join["thread_state"],
            fixture["actors"]["bob"]["threadStateAfterJoin"]
        );

        let bob_message = handle_request(BridgeRequest::MlsProcessMessage(
            MlsProcessMessageRequest {
                local_mls_state: bob_join["local_mls_state"]
                    .as_str()
                    .expect("bob joined mls state should exist")
                    .to_owned(),
                thread_state: bob_join["thread_state"]
                    .as_str()
                    .expect("bob joined thread state should exist")
                    .to_owned(),
                wire_message: fixture["message"]["wireMessage"]
                    .as_str()
                    .expect("mls wire message should exist")
                    .to_owned(),
            },
        ))
        .expect("bob should decrypt the MLS vector");
        assert_eq!(
            bob_message["plaintext"],
            fixture["message"]["expectedPlaintext"]
        );

        let carol_join = handle_request(BridgeRequest::MlsJoinGroup(MlsJoinGroupRequest {
            local_mls_state: fixture["actors"]["carol"]["initialState"]
                .as_str()
                .expect("carol mls state should exist")
                .to_owned(),
            local_user_id: fixture["actors"]["carol"]["userId"]
                .as_str()
                .expect("carol user should exist")
                .to_owned(),
            thread_bootstrap,
        }))
        .expect("carol should join the MLS group vector");
        assert_eq!(
            carol_join["thread_state"],
            fixture["actors"]["carol"]["threadStateAfterJoin"]
        );

        let carol_message = handle_request(BridgeRequest::MlsProcessMessage(
            MlsProcessMessageRequest {
                local_mls_state: carol_join["local_mls_state"]
                    .as_str()
                    .expect("carol joined mls state should exist")
                    .to_owned(),
                thread_state: carol_join["thread_state"]
                    .as_str()
                    .expect("carol joined thread state should exist")
                    .to_owned(),
                wire_message: fixture["message"]["wireMessage"]
                    .as_str()
                    .expect("mls wire message should exist")
                    .to_owned(),
            },
        ))
        .expect("carol should decrypt the MLS vector");
        assert_eq!(
            carol_message["plaintext"],
            fixture["message"]["expectedPlaintext"]
        );
    }

    #[test]
    fn signal_tampered_wire_message_is_rejected() {
        let fixture_path = test_vectors_dir().join("signal-direct-v1.json");
        let fixture_raw = fs::read_to_string(&fixture_path).expect("signal fixture should load");
        let fixture: serde_json::Value =
            serde_json::from_str(&fixture_raw).expect("signal fixture should decode");
        let mut tampered_wire = fixture["messages"][0]["wireMessage"]
            .as_str()
            .expect("signal wire should exist")
            .to_owned();
        let last_index = tampered_wire.len().saturating_sub(2);
        tampered_wire.replace_range(last_index..last_index + 1, "A");

        let result = handle_request(BridgeRequest::SignalDecrypt(SignalDecryptRequest {
            local_signal_state: fixture["actors"]["bob"]["initialState"]
                .as_str()
                .expect("bob state should exist")
                .to_owned(),
            local_user_id: fixture["actors"]["bob"]["userId"]
                .as_str()
                .expect("bob user should exist")
                .to_owned(),
            message_kind: fixture["messages"][0]["messageKind"]
                .as_str()
                .expect("signal message kind should exist")
                .to_owned(),
            remote_user_id: fixture["actors"]["alice"]["userId"]
                .as_str()
                .expect("alice user should exist")
                .to_owned(),
            wire_message: tampered_wire,
        }));

        assert!(result.is_err(), "tampered Signal ciphertext should be rejected");
    }

    #[test]
    fn mls_tampered_wire_message_is_rejected() {
        let fixture_path = test_vectors_dir().join("mls-group-v1.json");
        let fixture_raw = fs::read_to_string(&fixture_path).expect("mls fixture should load");
        let fixture: serde_json::Value =
            serde_json::from_str(&fixture_raw).expect("mls fixture should decode");
        let thread_bootstrap = MlsThreadBootstrap {
            ciphersuite: fixture["threadBootstrap"]["ciphersuite"]
                .as_str()
                .expect("bootstrap ciphersuite should exist")
                .to_owned(),
            group_id: fixture["threadBootstrap"]["groupId"]
                .as_str()
                .expect("bootstrap group id should exist")
                .to_owned(),
            welcomes: fixture["threadBootstrap"]["welcomes"]
                .as_array()
                .expect("bootstrap welcomes should exist")
                .iter()
                .map(|welcome| MlsWelcomeEnvelope {
                    to_user_id: welcome["toUserId"]
                        .as_str()
                        .expect("welcome user should exist")
                        .to_owned(),
                    welcome: welcome["welcome"]
                        .as_str()
                        .expect("welcome payload should exist")
                        .to_owned(),
                })
                .collect(),
        };

        let bob_join = handle_request(BridgeRequest::MlsJoinGroup(MlsJoinGroupRequest {
            local_mls_state: fixture["actors"]["bob"]["initialState"]
                .as_str()
                .expect("bob mls state should exist")
                .to_owned(),
            local_user_id: fixture["actors"]["bob"]["userId"]
                .as_str()
                .expect("bob user should exist")
                .to_owned(),
            thread_bootstrap,
        }))
        .expect("bob should join the MLS group vector");

        let mut tampered_wire = fixture["message"]["wireMessage"]
            .as_str()
            .expect("mls wire message should exist")
            .to_owned();
        let last_index = tampered_wire.len().saturating_sub(2);
        tampered_wire.replace_range(last_index..last_index + 1, "A");

        let result = handle_request(BridgeRequest::MlsProcessMessage(MlsProcessMessageRequest {
            local_mls_state: bob_join["local_mls_state"]
                .as_str()
                .expect("bob joined mls state should exist")
                .to_owned(),
            thread_state: bob_join["thread_state"]
                .as_str()
                .expect("bob joined thread state should exist")
                .to_owned(),
            wire_message: tampered_wire,
        }));

        assert!(result.is_err(), "tampered MLS ciphertext should be rejected");
    }
}
