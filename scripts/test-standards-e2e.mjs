import { randomBytes, randomUUID, generateKeyPairSync } from "node:crypto";
import { mkdtemp, cp, rm } from "node:fs/promises";
import { spawn, spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT_DIR = path.resolve(__dirname, "..");
const HELPER_PATH = path.join(ROOT_DIR, "native", "protocol-core", "target", "release", "notrus-protocol-core");
const RELAY_ORIGIN = process.env.NOTRUS_E2E_RELAY_ORIGIN ?? "http://127.0.0.1:3302";
const RELAY_PORT = Number(new URL(RELAY_ORIGIN).port || 80);
const SAFE_CHILD_PATH = "/usr/bin:/bin:/usr/sbin:/sbin";

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function assertResponseKeys(payload, expectedKeys, message) {
  const actual = Object.keys(payload).sort((a, b) => a.localeCompare(b));
  const expected = [...expectedKeys].sort((a, b) => a.localeCompare(b));
  assert(JSON.stringify(actual) === JSON.stringify(expected), `${message} Expected ${expected.join(", ")}, got ${actual.join(", ")}.`);
}

function generatePublicJwk() {
  const { publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = publicKey.export({ format: "jwk" });
  return {
    crv: jwk.crv,
    kty: jwk.kty,
    x: jwk.x,
    y: jwk.y,
  };
}

function base64(bytes = 32) {
  return randomBytes(bytes).toString("base64");
}

function now() {
  return new Date().toISOString();
}

function bridge(request) {
  const run = spawnSync(HELPER_PATH, {
    input: JSON.stringify(request),
    encoding: "utf8",
  });

  if (run.status !== 0) {
    throw new Error(run.stderr.trim() || `Standards helper failed with status ${run.status}.`);
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

async function waitForRelay(origin, attempts = 80) {
  for (let index = 0; index < attempts; index += 1) {
    try {
      const response = await fetch(`${origin}/api/health`);
      if (response.ok) {
        return await response.json();
      }
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 150));
  }

  throw new Error("Timed out waiting for the standards relay.");
}

async function api(pathname, { method = "GET", body, token } = {}) {
  const response = await fetch(`${RELAY_ORIGIN}${pathname}`, {
    method,
    headers: {
      Accept: "application/json",
      ...(body ? { "Content-Type": "application/json" } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await response.json();
  if (!response.ok) {
    throw new Error(data.error || `Relay returned HTTP ${response.status}.`);
  }
  return data;
}

async function registerUser(profile) {
  const response = await api("/api/bootstrap/register", {
    method: "POST",
    body: {
      displayName: profile.displayName,
      encryptionPublicJwk: generatePublicJwk(),
      fingerprint: profile.standards.fingerprint,
      mlsKeyPackage: profile.standards.mlsKeyPackage,
      prekeyCreatedAt: now(),
      prekeyFingerprint: base64(16),
      prekeyPublicJwk: generatePublicJwk(),
      prekeySignature: base64(48),
      recoveryFingerprint: profile.recoveryFingerprint,
      recoveryPublicJwk: profile.recoveryPublicJwk,
      signalBundle: profile.standards.signalBundle,
      signingPublicJwk: generatePublicJwk(),
      userId: profile.id,
      username: profile.username,
    },
  });
  assert(response.session?.token, `Registration did not issue a session for ${profile.username}.`);
  profile.session = response.session;
  profile.registeredUser = response.user;
}

async function syncProfile(profile) {
  return api("/api/sync/state", { token: profile.session.token });
}

async function searchContact(profile, query, expectedUserId) {
  const search = await api(`/api/directory/search?q=${encodeURIComponent(query)}`, {
    token: profile.session.token,
  });
  const result = search.results?.find((candidate) => candidate.id === expectedUserId);
  assert(result?.contactHandle, `Directory search did not return a contact handle for ${query}.`);
  return result;
}

function createProfile(displayName, username) {
  const id = randomUUID().toLowerCase();
  const recoveryPublicJwk = generatePublicJwk();
  const rawStandards = bridge({
    command: "create-identity",
    display_name: displayName,
    thread_user_id: id,
    username,
  });
  const standards = {
    fingerprint: rawStandards.fingerprint,
    mlsKeyPackage: normalizeMlsKeyPackage(rawStandards.mls_key_package),
    mlsState: rawStandards.mls_state,
    signalBundle: normalizeSignalBundle(rawStandards.signal_bundle),
    signalState: rawStandards.signal_state,
  };

  return {
    displayName,
    id,
    recoveryFingerprint: base64(16),
    recoveryPublicJwk,
    standards,
    username,
  };
}

function updateSignalState(profile, signalState) {
  profile.standards.signalState = signalState;
}

function updateMlsState(profile, mlsState) {
  profile.standards.mlsState = mlsState;
}

async function main() {
  const helperSnapshot = bridge({ command: "profile-snapshot" });
  assert(helperSnapshot.signal?.backend === "libsignal-protocol", "The standards helper is not exposing the Signal core.");
  assert(helperSnapshot.mls?.backend === "openmls", "The standards helper is not exposing the OpenMLS core.");

  const useExistingRelay = process.env.NOTRUS_E2E_USE_EXISTING_RELAY === "true";
  const tempRoot = useExistingRelay ? null : await mkdtemp(path.join(tmpdir(), "notrus-standards-relay-"));
  if (tempRoot) {
    await cp(path.join(ROOT_DIR, "server.js"), path.join(tempRoot, "server.js"));
    await cp(path.join(ROOT_DIR, "protocol-policy.js"), path.join(tempRoot, "protocol-policy.js"));
  }

  const relayChild = useExistingRelay
    ? null
    : spawn(process.execPath, ["server.js"], {
        cwd: tempRoot,
        env: {
          ...process.env,
          PATH: SAFE_CHILD_PATH,
          NODE_ENV: "production",
          NOTRUS_ENABLE_DEVELOPMENT_COMPAT_ROUTES: "false",
          NOTRUS_ENABLE_LEGACY_API: "false",
          PORT: String(RELAY_PORT),
          NOTRUS_PROTOCOL_POLICY: "require-standards",
        },
        stdio: ["ignore", "pipe", "pipe"],
      });

  try {
    const health = await waitForRelay(RELAY_ORIGIN);
    assert(health.protocolPolicy?.mode === "require-standards", "Relay did not start in strict standards mode.");

    const alice = createProfile("Alice", `alice-${Date.now()}`);
    const bob = createProfile("Bob", `bob-${Date.now()}`);
    const carol = createProfile("Carol", `carol-${Date.now()}`);

    await registerUser(alice);
    await registerUser(bob);
    await registerUser(carol);

    const bobContact = await searchContact(alice, bob.username, bob.id);
    const carolContact = await searchContact(alice, carol.username, carol.id);

    const legacyCompatibilityAttempt = await fetch(`${RELAY_ORIGIN}/api/threads`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        id: randomUUID(),
        createdAt: now(),
        createdBy: alice.id,
        participantIds: [alice.id, bob.id],
        protocol: "pairwise-v2",
        title: "legacy",
        envelopes: [],
      }),
    });
    assert(legacyCompatibilityAttempt.status === 410, "Production relay unexpectedly exposed the legacy thread API.");

    const legacyProtocolAttempt = await fetch(`${RELAY_ORIGIN}/api/routing/threads`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${alice.session.token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        createdAt: now(),
        id: randomUUID(),
        participantHandles: [bobContact.contactHandle],
        protocol: "pairwise-v2",
        title: "legacy",
      }),
    });
    assert(legacyProtocolAttempt.status === 412, "Strict relay unexpectedly allowed a legacy protocol through production routing.");

    const directThreadId = randomUUID().toLowerCase();
    const directThread = await api("/api/routing/threads", {
      method: "POST",
      token: alice.session.token,
      body: {
        createdAt: now(),
        id: directThreadId,
        participantHandles: [bobContact.contactHandle],
        protocol: "signal-pqxdh-double-ratchet-v1",
        title: "Alice and Bob",
      },
    });
    assert(directThread.threadId === directThreadId, "Production direct thread creation returned an unexpected thread id.");

    const aliceDirectSync = await syncProfile(alice);
    const aliceDirectThread = aliceDirectSync.threads.find((thread) => thread.id === directThreadId);
    assert(aliceDirectThread?.mailboxHandle, "Alice sync did not return a direct mailbox handle.");
    assert(aliceDirectThread?.deliveryCapability, "Alice sync did not return a direct delivery capability.");

    const aliceToBob = bridge({
      command: "signal-encrypt",
      local_signal_state: alice.standards.signalState,
      local_user_id: alice.id,
      plaintext: "hello from signal",
      remote_bundle: toHelperSignalBundle(bob.standards.signalBundle),
      remote_user_id: bob.id,
    });
    updateSignalState(alice, aliceToBob.local_signal_state);

    const directMessage = await api(`/api/mailboxes/${aliceDirectThread.mailboxHandle}/messages`, {
      method: "POST",
      token: aliceDirectThread.deliveryCapability,
      body: {
        createdAt: now(),
        id: randomUUID().toLowerCase(),
        messageKind: aliceToBob.message_kind,
        protocol: "signal-pqxdh-double-ratchet-v1",
        wireMessage: aliceToBob.wire_message,
      },
    });
    assertResponseKeys(directMessage, ["messageId", "ok"], "Production message response leaked extra metadata.");

    const bobSync = await syncProfile(bob);
    const bobDirectThread = bobSync.threads.find((thread) => thread.id === directThreadId);
    assert(bobDirectThread, "Bob did not receive the Signal direct thread.");
    assert(bobDirectThread.mailboxHandle, "Bob sync did not return a direct mailbox handle.");
    assert(bobDirectThread.deliveryCapability, "Bob sync did not return a direct delivery capability.");
    const bobDirectMessage = bobDirectThread.messages.at(-1);
    const bobOpened = bridge({
      command: "signal-decrypt",
      local_signal_state: bob.standards.signalState,
      local_user_id: bob.id,
      message_kind: bobDirectMessage.messageKind,
      remote_user_id: alice.id,
      wire_message: bobDirectMessage.wireMessage,
    });
    updateSignalState(bob, bobOpened.local_signal_state);
    assert(bobOpened.plaintext === "hello from signal", "Bob failed to decrypt Alice's Signal message.");

    const bobToAlice = bridge({
      command: "signal-encrypt",
      local_signal_state: bob.standards.signalState,
      local_user_id: bob.id,
      plaintext: "reply from signal",
      remote_bundle: toHelperSignalBundle(alice.standards.signalBundle),
      remote_user_id: alice.id,
    });
    updateSignalState(bob, bobToAlice.local_signal_state);

    const replyMessage = await api(`/api/mailboxes/${bobDirectThread.mailboxHandle}/messages`, {
      method: "POST",
      token: bobDirectThread.deliveryCapability,
      body: {
        createdAt: now(),
        id: randomUUID().toLowerCase(),
        messageKind: bobToAlice.message_kind,
        protocol: "signal-pqxdh-double-ratchet-v1",
        wireMessage: bobToAlice.wire_message,
      },
    });
    assertResponseKeys(replyMessage, ["messageId", "ok"], "Production reply response leaked extra metadata.");

    const aliceReplySync = await syncProfile(alice);
    const aliceDirectThreadAfterReply = aliceReplySync.threads.find((thread) => thread.id === directThreadId);
    const aliceDirectReply = aliceDirectThreadAfterReply.messages.at(-1);
    const aliceOpened = bridge({
      command: "signal-decrypt",
      local_signal_state: alice.standards.signalState,
      local_user_id: alice.id,
      message_kind: aliceDirectReply.messageKind,
      remote_user_id: bob.id,
      wire_message: aliceDirectReply.wireMessage,
    });
    updateSignalState(alice, aliceOpened.local_signal_state);
    assert(aliceOpened.plaintext === "reply from signal", "Alice failed to decrypt Bob's Signal reply.");

    const groupThreadId = randomUUID().toLowerCase();
    const rawMlsGroup = bridge({
      command: "mls-create-group",
      creator_mls_state: alice.standards.mlsState,
      creator_user_id: alice.id,
      participant_key_packages: {
        [bob.id]: toHelperMlsKeyPackage(bob.standards.mlsKeyPackage),
        [carol.id]: toHelperMlsKeyPackage(carol.standards.mlsKeyPackage),
      },
      participant_user_ids: [alice.id, bob.id, carol.id],
      thread_id: groupThreadId,
    });
    const mlsGroup = {
      creatorMlsState: rawMlsGroup.creator_mls_state,
      threadBootstrap: normalizeMlsBootstrap(rawMlsGroup.thread_bootstrap),
      threadState: rawMlsGroup.thread_state,
    };
    updateMlsState(alice, mlsGroup.creatorMlsState);

    const groupThread = await api("/api/routing/threads", {
      method: "POST",
      token: alice.session.token,
      body: {
        createdAt: now(),
        id: groupThreadId,
        mlsBootstrap: mlsGroup.threadBootstrap,
        participantHandles: [bobContact.contactHandle, carolContact.contactHandle],
        protocol: "mls-rfc9420-v1",
        title: "Alice, Bob, Carol",
      },
    });
    assert(groupThread.threadId === groupThreadId, "Production MLS thread creation returned an unexpected thread id.");

    const bobGroupSync = await syncProfile(bob);
    const bobGroupThread = bobGroupSync.threads.find((thread) => thread.id === groupThreadId);
    assert(bobGroupThread?.mlsBootstrap?.welcomes?.length === 1, "Bob did not receive a user-scoped MLS welcome.");
    const bobGroupJoin = bridge({
      command: "mls-join-group",
      local_mls_state: bob.standards.mlsState,
      local_user_id: bob.id,
      thread_bootstrap: toHelperMlsBootstrap(bobGroupThread.mlsBootstrap),
    });
    updateMlsState(bob, bobGroupJoin.local_mls_state);

    const carolGroupSync = await syncProfile(carol);
    const carolGroupThread = carolGroupSync.threads.find((thread) => thread.id === groupThreadId);
    assert(carolGroupThread?.mlsBootstrap?.welcomes?.length === 1, "Carol did not receive a user-scoped MLS welcome.");
    const carolGroupJoin = bridge({
      command: "mls-join-group",
      local_mls_state: carol.standards.mlsState,
      local_user_id: carol.id,
      thread_bootstrap: toHelperMlsBootstrap(carolGroupThread.mlsBootstrap),
    });
    updateMlsState(carol, carolGroupJoin.local_mls_state);

    const aliceGroupMessage = bridge({
      command: "mls-encrypt-message",
      local_mls_state: alice.standards.mlsState,
      plaintext: "hello from mls",
      thread_state: mlsGroup.threadState,
    });
    updateMlsState(alice, aliceGroupMessage.local_mls_state);

    const aliceGroupSync = await syncProfile(alice);
    const aliceGroupThread = aliceGroupSync.threads.find((thread) => thread.id === groupThreadId);
    assert(aliceGroupThread?.mailboxHandle, "Alice sync did not return an MLS mailbox handle.");
    assert(aliceGroupThread?.deliveryCapability, "Alice sync did not return an MLS delivery capability.");

    const groupMessage = await api(`/api/mailboxes/${aliceGroupThread.mailboxHandle}/messages`, {
      method: "POST",
      token: aliceGroupThread.deliveryCapability,
      body: {
        createdAt: now(),
        id: randomUUID().toLowerCase(),
        messageKind: "mls-application",
        protocol: "mls-rfc9420-v1",
        wireMessage: aliceGroupMessage.wire_message,
      },
    });
    assertResponseKeys(groupMessage, ["messageId", "ok"], "Production MLS message response leaked extra metadata.");

    const bobGroupSyncAfterMessage = await syncProfile(bob);
    const bobGroupThreadAfterMessage = bobGroupSyncAfterMessage.threads.find((thread) => thread.id === groupThreadId);
    const bobMlsMessage = bobGroupThreadAfterMessage.messages.at(-1);
    const bobOpenedMls = bridge({
      command: "mls-process-message",
      local_mls_state: bob.standards.mlsState,
      thread_state: bobGroupJoin.thread_state,
      wire_message: bobMlsMessage.wireMessage,
    });
    assert(bobOpenedMls.plaintext === "hello from mls", "Bob failed to decrypt Alice's MLS group message.");

    const carolGroupSyncAfterMessage = await syncProfile(carol);
    const carolGroupThreadAfterMessage = carolGroupSyncAfterMessage.threads.find((thread) => thread.id === groupThreadId);
    const carolMlsMessage = carolGroupThreadAfterMessage.messages.at(-1);
    const carolOpenedMls = bridge({
      command: "mls-process-message",
      local_mls_state: carol.standards.mlsState,
      thread_state: carolGroupJoin.thread_state,
      wire_message: carolMlsMessage.wireMessage,
    });
    assert(carolOpenedMls.plaintext === "hello from mls", "Carol failed to decrypt Alice's MLS group message.");

    console.log(JSON.stringify({
      ok: true,
      protocolPolicy: health.protocolPolicy?.mode,
      verified: [
        "strict-standards-policy",
        "production-compat-routes-disabled",
        "production-opaque-contact-routing",
        "production-mailbox-signal-round-trip",
        "production-mailbox-mls-group-round-trip",
        "production-user-scoped-mls-welcomes",
        "minimal-production-message-responses",
      ],
    }, null, 2));
  } finally {
    relayChild?.kill("SIGTERM");
    if (tempRoot) {
      await rm(tempRoot, { force: true, recursive: true });
    }
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
