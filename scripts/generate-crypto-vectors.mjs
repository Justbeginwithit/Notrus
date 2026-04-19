import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT_DIR = path.resolve(__dirname, "..");
const HELPER_PATH = path.join(ROOT_DIR, "native", "protocol-core", "target", "release", "notrus-protocol-core");
const VECTORS_DIR = path.join(ROOT_DIR, "native", "protocol-core", "test-vectors");

function bridge(request) {
  const run = spawnSync(HELPER_PATH, {
    input: JSON.stringify(request),
    encoding: "utf8",
  });

  if (run.status !== 0) {
    throw new Error(run.stderr.trim() || `Helper failed with status ${run.status}.`);
  }

  return JSON.parse(run.stdout);
}

function normalizeSignalBundle(bundle) {
  return {
    deviceId: bundle.device_id,
    identityKey: bundle.identity_key,
    kyberPreKeyId: bundle.kyber_pre_key_id,
    kyberPreKeyPublic: bundle.kyber_pre_key_public,
    kyberPreKeySignature: bundle.kyber_pre_key_signature,
    preKeyId: bundle.pre_key_id,
    preKeyPublic: bundle.pre_key_public,
    registrationId: bundle.registration_id,
    signedPreKeyId: bundle.signed_pre_key_id,
    signedPreKeyPublic: bundle.signed_pre_key_public,
    signedPreKeySignature: bundle.signed_pre_key_signature,
  };
}

function normalizeMlsKeyPackage(bundle) {
  return {
    ciphersuite: bundle.ciphersuite,
    keyPackage: bundle.key_package,
  };
}

function normalizeMlsBootstrap(bootstrap) {
  return {
    ciphersuite: bootstrap.ciphersuite,
    groupId: bootstrap.group_id,
    welcomes: bootstrap.welcomes.map((welcome) => ({
      toUserId: welcome.to_user_id,
      welcome: welcome.welcome,
    })),
  };
}

function toHelperSignalBundle(bundle) {
  return {
    device_id: bundle.deviceId,
    identity_key: bundle.identityKey,
    kyber_pre_key_id: bundle.kyberPreKeyId,
    kyber_pre_key_public: bundle.kyberPreKeyPublic,
    kyber_pre_key_signature: bundle.kyberPreKeySignature,
    pre_key_id: bundle.preKeyId,
    pre_key_public: bundle.preKeyPublic,
    registration_id: bundle.registrationId,
    signed_pre_key_id: bundle.signedPreKeyId,
    signed_pre_key_public: bundle.signedPreKeyPublic,
    signed_pre_key_signature: bundle.signedPreKeySignature,
  };
}

function toHelperMlsKeyPackage(bundle) {
  return {
    ciphersuite: bundle.ciphersuite,
    key_package: bundle.keyPackage,
  };
}

function toHelperMlsBootstrap(bootstrap) {
  return {
    ciphersuite: bootstrap.ciphersuite,
    group_id: bootstrap.groupId,
    welcomes: bootstrap.welcomes.map((welcome) => ({
      to_user_id: welcome.toUserId,
      welcome: welcome.welcome,
    })),
  };
}

function createActor(displayName, threadUserId, username) {
  const created = bridge({
    command: "create-identity",
    display_name: displayName,
    thread_user_id: threadUserId,
    username,
  });

  return {
    displayName,
    mlsKeyPackage: normalizeMlsKeyPackage(created.mls_key_package),
    mlsState: created.mls_state,
    signalBundle: normalizeSignalBundle(created.signal_bundle),
    signalState: created.signal_state,
    userId: threadUserId,
    username,
  };
}

function buildSignalVector(snapshot) {
  const alice = createActor("Alice", "signal-vector-alice", "signal_vector_alice");
  const bob = createActor("Bob", "signal-vector-bob", "signal_vector_bob");

  const aliceToBob = bridge({
    command: "signal-encrypt",
    local_signal_state: alice.signalState,
    local_user_id: alice.userId,
    plaintext: "hello from signal vector",
    remote_bundle: toHelperSignalBundle(bob.signalBundle),
    remote_user_id: bob.userId,
  });

  const bobOpened = bridge({
    command: "signal-decrypt",
    local_signal_state: bob.signalState,
    local_user_id: bob.userId,
    message_kind: aliceToBob.message_kind,
    remote_user_id: alice.userId,
    wire_message: aliceToBob.wire_message,
  });

  const bobToAlice = bridge({
    command: "signal-encrypt",
    local_signal_state: bobOpened.local_signal_state,
    local_user_id: bob.userId,
    plaintext: "reply from signal vector",
    remote_bundle: toHelperSignalBundle(alice.signalBundle),
    remote_user_id: alice.userId,
  });

  return {
    generatedBy: snapshot.coreVersion,
    messageEncoding: snapshot.signal.messageEncoding,
    messageWrapper: snapshot.signal.messageWrapper,
    protocol: "signal-pqxdh-double-ratchet-v1",
    schemaVersion: 1,
    signal: {
      backend: snapshot.signal.backend,
      upstreamRev: snapshot.signal.upstreamRev,
    },
    transport: snapshot.transport,
    actors: {
      alice: {
        bundle: alice.signalBundle,
        initialState: alice.signalState,
        stateAfterFirstSend: aliceToBob.local_signal_state,
        userId: alice.userId,
      },
      bob: {
        bundle: bob.signalBundle,
        initialState: bob.signalState,
        stateAfterFirstReceive: bobOpened.local_signal_state,
        userId: bob.userId,
      },
    },
    messages: [
      {
        direction: "alice->bob",
        expectedPlaintext: "hello from signal vector",
        messageKind: aliceToBob.message_kind,
        wireMessage: aliceToBob.wire_message,
      },
      {
        direction: "bob->alice",
        expectedPlaintext: "reply from signal vector",
        messageKind: bobToAlice.message_kind,
        wireMessage: bobToAlice.wire_message,
      },
    ],
  };
}

function buildMlsVector(snapshot) {
  const alice = createActor("Alice", "mls-vector-alice", "mls_vector_alice");
  const bob = createActor("Bob", "mls-vector-bob", "mls_vector_bob");
  const carol = createActor("Carol", "mls-vector-carol", "mls_vector_carol");

  const created = bridge({
    command: "mls-create-group",
    creator_mls_state: alice.mlsState,
    creator_user_id: alice.userId,
    participant_key_packages: {
      [bob.userId]: toHelperMlsKeyPackage(bob.mlsKeyPackage),
      [carol.userId]: toHelperMlsKeyPackage(carol.mlsKeyPackage),
    },
    participant_user_ids: [alice.userId, bob.userId, carol.userId],
    thread_id: "mls-vector-thread",
  });

  const threadBootstrap = normalizeMlsBootstrap(created.thread_bootstrap);

  const bobJoin = bridge({
    command: "mls-join-group",
    local_mls_state: bob.mlsState,
    local_user_id: bob.userId,
    thread_bootstrap: toHelperMlsBootstrap(threadBootstrap),
  });

  const carolJoin = bridge({
    command: "mls-join-group",
    local_mls_state: carol.mlsState,
    local_user_id: carol.userId,
    thread_bootstrap: toHelperMlsBootstrap(threadBootstrap),
  });

  const aliceMessage = bridge({
    command: "mls-encrypt-message",
    local_mls_state: created.creator_mls_state,
    plaintext: "hello from mls vector",
    thread_state: created.thread_state,
  });

  return {
    ciphersuite: snapshot.mls.ciphersuite,
    generatedBy: snapshot.coreVersion,
    messageEncoding: snapshot.signal.messageEncoding,
    messageWrapper: snapshot.signal.messageWrapper,
    protocol: "mls-rfc9420-v1",
    schemaVersion: 1,
    mls: {
      backend: snapshot.mls.backend,
      basicCredentialVersion: snapshot.mls.basicCredentialVersion,
      openmlsRustCryptoVersion: snapshot.mls.openmlsRustCryptoVersion,
      openmlsVersion: snapshot.mls.openmlsVersion,
      rfc: snapshot.mls.rfc,
    },
    transport: snapshot.transport,
    actors: {
      alice: {
        initialState: alice.mlsState,
        keyPackage: alice.mlsKeyPackage,
        threadStateAfterCreate: created.thread_state,
        userId: alice.userId,
      },
      bob: {
        initialState: bob.mlsState,
        keyPackage: bob.mlsKeyPackage,
        threadStateAfterJoin: bobJoin.thread_state,
        userId: bob.userId,
      },
      carol: {
        initialState: carol.mlsState,
        keyPackage: carol.mlsKeyPackage,
        threadStateAfterJoin: carolJoin.thread_state,
        userId: carol.userId,
      },
    },
    threadBootstrap,
    message: {
      expectedPlaintext: "hello from mls vector",
      messageKind: "mls-application",
      wireMessage: aliceMessage.wire_message,
    },
  };
}

async function main() {
  const snapshot = bridge({ command: "profile-snapshot" });
  await mkdir(VECTORS_DIR, { recursive: true });

  const signalVector = buildSignalVector(snapshot);
  const mlsVector = buildMlsVector(snapshot);

  await writeFile(
    path.join(VECTORS_DIR, "signal-direct-v1.json"),
    JSON.stringify(signalVector, null, 2) + "\n",
    "utf8"
  );
  await writeFile(
    path.join(VECTORS_DIR, "mls-group-v1.json"),
    JSON.stringify(mlsVector, null, 2) + "\n",
    "utf8"
  );

  console.log(`Wrote crypto vectors to ${VECTORS_DIR}`);
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
