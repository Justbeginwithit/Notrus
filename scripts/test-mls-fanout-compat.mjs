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
const RELAY_ORIGIN = process.env.NOTRUS_E2E_RELAY_ORIGIN ?? "http://127.0.0.1:3311";
const RELAY_PORT = Number(new URL(RELAY_ORIGIN).port || 80);
const FANOUT_CIPHERSUITE = "MLS-compat-signal-fanout-v1";
const FANOUT_FORMAT = "notrus-mls-signal-fanout-v1";

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function now() {
  return new Date().toISOString();
}

function base64(bytes = 32) {
  return randomBytes(bytes).toString("base64");
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
  throw new Error("Timed out waiting for the relay.");
}

function createProfile(displayName, username) {
  const id = randomUUID().toLowerCase();
  const standards = bridge({
    command: "create-identity",
    display_name: displayName,
    thread_user_id: id,
    username,
  });
  return {
    displayName,
    id,
    username,
    recoveryFingerprint: base64(16),
    recoveryPublicJwk: generatePublicJwk(),
    signalBundle: normalizeSignalBundle(standards.signal_bundle),
    signalState: standards.signal_state,
  };
}

async function registerProfile(profile) {
  const response = await api("/api/bootstrap/register", {
    method: "POST",
    body: {
      displayName: profile.displayName,
      encryptionPublicJwk: generatePublicJwk(),
      fingerprint: base64(16),
      prekeyCreatedAt: now(),
      prekeyFingerprint: base64(16),
      prekeyPublicJwk: generatePublicJwk(),
      prekeySignature: base64(48),
      recoveryFingerprint: profile.recoveryFingerprint,
      recoveryPublicJwk: profile.recoveryPublicJwk,
      signalBundle: profile.signalBundle,
      signingPublicJwk: generatePublicJwk(),
      userId: profile.id,
      username: profile.username,
    },
  });
  profile.session = response.session;
}

async function searchHandle(profile, query, expectedUserId) {
  const response = await api(`/api/directory/search?q=${encodeURIComponent(query)}`, {
    token: profile.session.token,
  });
  const match = response.results?.find((candidate) => candidate.id === expectedUserId);
  assert(match?.contactHandle, `Missing contact handle for ${query}.`);
  return match.contactHandle;
}

function standardsPayload(text) {
  return JSON.stringify({
    attachments: [],
    text,
    version: 1,
  });
}

async function main() {
  const useExistingRelay = process.env.NOTRUS_E2E_USE_EXISTING_RELAY === "true";
  const tempRoot = useExistingRelay ? null : await mkdtemp(path.join(tmpdir(), "notrus-fanout-relay-"));
  if (tempRoot) {
    await cp(path.join(ROOT_DIR, "server.js"), path.join(tempRoot, "server.js"));
    await cp(path.join(ROOT_DIR, "protocol-policy.js"), path.join(tempRoot, "protocol-policy.js"));
  }

  const relayChild = useExistingRelay
    ? null
    : spawn("node", ["server.js"], {
        cwd: tempRoot,
        env: {
          ...process.env,
          NODE_ENV: "production",
          NOTRUS_ENABLE_DEVELOPMENT_COMPAT_ROUTES: "false",
          NOTRUS_ENABLE_LEGACY_API: "false",
          NOTRUS_PROTOCOL_POLICY: "require-standards",
          PORT: String(RELAY_PORT),
        },
        stdio: ["ignore", "pipe", "pipe"],
      });

  try {
    const health = await waitForRelay(RELAY_ORIGIN);
    assert(health.protocolPolicy?.mode === "require-standards", "Relay is not running in strict standards mode.");

    const suffix = Date.now().toString(36).slice(-6);
    const alice = createProfile("Alice Fanout", `af_${suffix}`);
    const bob = createProfile("Bob Fanout", `bf_${suffix}`);
    const carol = createProfile("Carol Fanout", `cf_${suffix}`);

    await registerProfile(alice);
    await registerProfile(bob);
    await registerProfile(carol);

    const bobHandle = await searchHandle(alice, bob.username, bob.id);
    const carolHandle = await searchHandle(alice, carol.username, carol.id);

    const threadId = randomUUID().toLowerCase();
    await api("/api/routing/threads", {
      method: "POST",
      token: alice.session.token,
      body: {
        createdAt: now(),
        id: threadId,
        mlsBootstrap: {
          ciphersuite: FANOUT_CIPHERSUITE,
          groupId: `fanout-signal:${threadId}`,
          welcomes: [
            { toUserId: bob.id, welcome: base64(32) },
            { toUserId: carol.id, welcome: base64(32) },
          ],
        },
        participantHandles: [bobHandle, carolHandle],
        protocol: "mls-rfc9420-v1",
        title: "",
      },
    });

    const aliceSync = await api("/api/sync/state", { token: alice.session.token });
    const aliceThread = aliceSync.threads.find((thread) => thread.id === threadId);
    assert(aliceThread?.mailboxHandle, "Alice sync did not return mailboxHandle.");
    assert(aliceThread?.deliveryCapability, "Alice sync did not return deliveryCapability.");

    const plaintext = standardsPayload("hello from fanout");
    const recipients = [];
    for (const recipient of [bob, carol]) {
      const encrypted = bridge({
        command: "signal-encrypt",
        local_signal_state: alice.signalState,
        local_user_id: alice.id,
        plaintext,
        remote_bundle: toHelperSignalBundle(recipient.signalBundle),
        remote_user_id: recipient.id,
      });
      alice.signalState = encrypted.local_signal_state;
      recipients.push({
        messageKind: encrypted.message_kind,
        toUserId: recipient.id,
        wireMessage: encrypted.wire_message,
      });
    }

    const wireEnvelope = JSON.stringify({
      format: FANOUT_FORMAT,
      senderId: alice.id,
      version: 1,
      recipients,
    });

    await api(`/api/mailboxes/${aliceThread.mailboxHandle}/messages`, {
      method: "POST",
      token: aliceThread.deliveryCapability,
      body: {
        createdAt: now(),
        id: randomUUID().toLowerCase(),
        messageKind: "mls-application",
        protocol: "mls-rfc9420-v1",
        wireMessage: wireEnvelope,
      },
    });

    const bobSync = await api("/api/sync/state", { token: bob.session.token });
    const bobThread = bobSync.threads.find((thread) => thread.id === threadId);
    const bobMessage = bobThread?.messages?.at(-1);
    assert(bobMessage?.wireMessage, "Bob did not receive the fanout wire envelope.");
    const parsedBobEnvelope = JSON.parse(bobMessage.wireMessage);
    const bobRecipient = parsedBobEnvelope.recipients.find((entry) => entry.toUserId === bob.id);
    assert(bobRecipient, "Bob recipient envelope missing.");
    const bobOpened = bridge({
      command: "signal-decrypt",
      local_signal_state: bob.signalState,
      local_user_id: bob.id,
      message_kind: bobRecipient.messageKind,
      remote_user_id: alice.id,
      wire_message: bobRecipient.wireMessage,
    });
    bob.signalState = bobOpened.local_signal_state;
    assert(JSON.parse(bobOpened.plaintext).text === "hello from fanout", "Bob failed to decrypt fanout payload.");

    const carolSync = await api("/api/sync/state", { token: carol.session.token });
    const carolThread = carolSync.threads.find((thread) => thread.id === threadId);
    const carolMessage = carolThread?.messages?.at(-1);
    assert(carolMessage?.wireMessage, "Carol did not receive the fanout wire envelope.");
    const parsedCarolEnvelope = JSON.parse(carolMessage.wireMessage);
    const carolRecipient = parsedCarolEnvelope.recipients.find((entry) => entry.toUserId === carol.id);
    assert(carolRecipient, "Carol recipient envelope missing.");
    const carolOpened = bridge({
      command: "signal-decrypt",
      local_signal_state: carol.signalState,
      local_user_id: carol.id,
      message_kind: carolRecipient.messageKind,
      remote_user_id: alice.id,
      wire_message: carolRecipient.wireMessage,
    });
    carol.signalState = carolOpened.local_signal_state;
    assert(JSON.parse(carolOpened.plaintext).text === "hello from fanout", "Carol failed to decrypt fanout payload.");

    console.log(
      JSON.stringify(
        {
          ok: true,
          verified: [
            "standards-group-thread-created",
            "mls-compatible-fanout-envelope-posted",
            "bob-fanout-decrypt-success",
            "carol-fanout-decrypt-success",
          ],
        },
        null,
        2
      )
    );
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
