package com.notrus.android.relay

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.notrus.android.model.AttachmentUploadRequest
import com.notrus.android.model.Jwk
import com.notrus.android.model.LocalIdentity
import com.notrus.android.model.RelayUser
import java.net.ServerSocket
import java.net.Socket
import java.nio.charset.StandardCharsets
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.runBlocking
import org.json.JSONArray
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class RelayClientInstrumentedTest {
    private lateinit var testRelay: TestRelay
    private lateinit var origin: String

    @Before
    fun setUp() {
        testRelay = TestRelay()
        origin = "http://127.0.0.1:${testRelay.port}"
    }

    @After
    fun tearDown() {
        testRelay.close()
    }

    @Test
    fun searchDirectoryReturnsRelayUsersFromResultsEnvelope() = runBlocking {
        testRelay.enqueue(
            status = 200,
            body = JSONObject()
                .put("mode", "exact-username-or-invite")
                .put(
                    "results",
                    JSONArray().put(
                        JSONObject()
                            .put("id", "user-b")
                            .put("username", "bob")
                            .put("displayName", "Bob")
                            .put("directoryCode", "ABCD-1234")
                            .put("fingerprint", "fp-b")
                            .put("createdAt", "2026-04-04T00:00:00Z")
                    )
                )
                .toString()
        )

        val users = RelayClient(origin = origin, sessionToken = "session-token").searchDirectory("bob")

        assertEquals(1, users.size)
        val first: RelayUser = users.first()
        assertEquals("user-b", first.id)
        assertEquals("bob", first.username)
        assertEquals("Bob", first.displayName)
    }

    @Test
    fun searchDirectoryParsesUnsigned32SignalRegistrationIdWithoutOverflow() = runBlocking {
        testRelay.enqueue(
            status = 200,
            body = JSONObject()
                .put("mode", "username-or-invite")
                .put(
                    "results",
                    JSONArray().put(
                        JSONObject()
                            .put("id", "user-b")
                            .put("username", "bob")
                            .put("displayName", "Bob")
                            .put("directoryCode", "ABCD-1234")
                            .put("fingerprint", "fp-b")
                            .put("createdAt", "2026-04-04T00:00:00Z")
                            .put(
                                "signalBundle",
                                JSONObject()
                                    .put("deviceId", 1)
                                    .put("identityKey", "identity")
                                    .put("kyberPreKeyId", 7)
                                    .put("kyberPreKeyPublic", "kyber-public")
                                    .put("kyberPreKeySignature", "kyber-signature")
                                    .put("preKeyId", 11)
                                    .put("preKeyPublic", "prekey-public")
                                    .put("registrationId", 3719580524L)
                                    .put("signedPreKeyId", 13)
                                    .put("signedPreKeyPublic", "signed-public")
                                    .put("signedPreKeySignature", "signed-signature")
                            )
                    )
                )
                .toString()
        )

        val users = RelayClient(origin = origin, sessionToken = "session-token").searchDirectory("bob")

        assertEquals(1, users.size)
        val bundle = users.first().signalBundle
        assertNotNull(bundle)
        assertEquals(3719580524L.toInt(), bundle?.registrationId)
    }

    @Test
    fun searchDirectorySurfacesPlainTextServerErrors() = runBlocking {
        testRelay.enqueue(status = 400, body = "The invite code is invalid.", contentType = "text/plain; charset=utf-8")

        val error = runCatching {
            RelayClient(origin = origin, sessionToken = "session-token").searchDirectory("invalid")
        }.exceptionOrNull()

        assertNotNull(error)
        assertTrue(error is IllegalStateException)
        assertTrue(error?.message?.contains("The invite code is invalid.") == true)
    }

    @Test
    fun createDirectThreadReturnsThreadIdFromRelay() = runBlocking {
        testRelay.enqueue(
            status = 201,
            body = JSONObject()
                .put("ok", true)
                .put("threadId", "thread-direct-1")
                .toString()
        )

        val threadId = RelayClient(origin = origin, sessionToken = "session-token").createDirectThread("contact-handle-1")

        assertEquals("thread-direct-1", threadId)
        assertTrue(testRelay.requests.first().requestLine.startsWith("POST /api/routing/threads"))
    }

    @Test
    fun postMlsMessageUsesMlsProtocolAndApplicationKind() = runBlocking {
        testRelay.enqueue(
            status = 201,
            body = JSONObject()
                .put("ok", true)
                .put("messageId", "mls-message-1")
                .toString()
        )

        val messageId = RelayClient(origin = origin).postMlsMessage(
            mailboxHandle = "mailbox-group-1",
            deliveryCapability = "delivery-capability",
            wireMessage = "{\"format\":\"notrus-mls-signal-fanout-v1\"}",
        )

        assertEquals("mls-message-1", messageId)
        assertTrue(testRelay.requests.first().requestLine.startsWith("POST /api/mailboxes/mailbox-group-1/messages"))
        assertEquals("Bearer delivery-capability", testRelay.requests.first().headers["authorization"])
        assertTrue(testRelay.requests.first().body.contains("\"protocol\":\"mls-rfc9420-v1\""))
        assertTrue(testRelay.requests.first().body.contains("\"messageKind\":\"mls-application\""))
    }

    @Test
    fun syncParsesMlsBootstrapMetadataForGroupThreads() = runBlocking {
        testRelay.enqueue(
            status = 200,
            body = JSONObject()
                .put("directoryDiscoveryMode", "username-or-invite")
                .put("users", JSONArray())
                .put(
                    "threads",
                    JSONArray().put(
                        JSONObject()
                            .put("id", "thread-group-1")
                            .put("title", "")
                            .put("protocol", "mls-rfc9420-v1")
                            .put("createdAt", "2026-04-21T00:00:00Z")
                            .put("createdBy", "user-a")
                            .put("participantIds", JSONArray().put("user-a").put("user-b").put("user-c"))
                            .put("messages", JSONArray())
                            .put(
                                "mlsBootstrap",
                                JSONObject()
                                    .put("ciphersuite", "MLS-compat-signal-fanout-v1")
                                    .put("groupId", "fanout-signal:thread-group-1")
                                    .put(
                                        "welcomes",
                                        JSONArray().put(
                                            JSONObject()
                                                .put("toUserId", "user-b")
                                                .put("welcome", "ZmFrZS13ZWxjb21l")
                                        )
                                    )
                            )
                    )
                )
                .toString()
        )

        val sync = RelayClient(origin = origin, sessionToken = "session-token").sync()

        assertEquals(1, sync.threads.size)
        val thread = sync.threads.first()
        assertEquals("mls-rfc9420-v1", thread.protocol)
        assertEquals("MLS-compat-signal-fanout-v1", thread.mlsBootstrap?.ciphersuite)
        assertEquals("fanout-signal:thread-group-1", thread.mlsBootstrap?.groupId)
        assertEquals(1, thread.mlsBootstrap?.welcomes?.size)
    }

    @Test
    fun uploadAttachmentUsesMailboxCapabilityAndReturnsAttachmentId() = runBlocking {
        testRelay.enqueue(
            status = 201,
            body = JSONObject()
                .put("ok", true)
                .put("attachmentId", "attachment-1")
                .toString()
        )

        val attachmentId = RelayClient(origin = origin).uploadAttachment(
            mailboxHandle = "mailbox-1",
            deliveryCapability = "delivery-capability",
            attachment = AttachmentUploadRequest(
                byteLength = 512,
                ciphertext = "Y2lwaGVydGV4dA==",
                createdAt = "2026-04-21T00:00:00Z",
                id = "attachment-1",
                iv = "aXY=",
                senderId = "user-a",
                sha256 = "deadbeef",
                threadId = "thread-1",
                transportPadding = null,
            ),
        )

        assertEquals("attachment-1", attachmentId)
        assertTrue(testRelay.requests.first().requestLine.startsWith("POST /api/mailboxes/mailbox-1/attachments"))
        assertEquals("Bearer delivery-capability", testRelay.requests.first().headers["authorization"])
        assertTrue(testRelay.requests.first().body.contains("\"ciphertext\":\"Y2lwaGVydGV4dA==\""))
    }

    @Test
    fun fetchAttachmentUsesMailboxCapabilityAndParsesRelayPayload() = runBlocking {
        testRelay.enqueue(
            status = 200,
            body = JSONObject()
                .put("byteLength", 512)
                .put("ciphertext", "Y2lwaGVydGV4dA==")
                .put("createdAt", "2026-04-21T00:00:00Z")
                .put("id", "attachment-1")
                .put("iv", "aXY=")
                .put("senderId", "user-a")
                .put("sha256", "deadbeef")
                .put("threadId", "thread-1")
                .toString()
        )

        val attachment = RelayClient(origin = origin).fetchAttachment(
            mailboxHandle = "mailbox-1",
            deliveryCapability = "delivery-capability",
            attachmentId = "attachment-1",
        )

        assertEquals("attachment-1", attachment.id)
        assertEquals("thread-1", attachment.threadId)
        assertEquals("Bearer delivery-capability", testRelay.requests.first().headers["authorization"])
        assertTrue(testRelay.requests.first().requestLine.startsWith("GET /api/mailboxes/mailbox-1/attachments/attachment-1"))
    }

    @Test
    fun registerRetriesPowChallengeWithHeadersBeforeSendingBody() = runBlocking {
        testRelay.enqueue(
            status = 428,
            body = JSONObject()
                .put(
                    "powChallenge",
                    JSONObject()
                        .put("difficultyBits", 0)
                        .put("token", "challenge-token")
                        .put("tokenField", "X-Notrus-Pow-Token")
                        .put("nonceField", "X-Notrus-Pow-Nonce")
                )
                .toString()
        )
        testRelay.enqueue(
            status = 200,
            body = JSONObject()
                .put(
                    "user",
                    JSONObject()
                        .put("id", "user-a")
                        .put("username", "alice")
                        .put("displayName", "Alice")
                        .put("directoryCode", "NTRS-1234")
                        .put("fingerprint", "fp-a")
                        .put("createdAt", "2026-04-09T00:00:00Z")
                )
                .toString()
        )

        val identity = LocalIdentity(
            id = "user-a",
            username = "alice",
            displayName = "Alice",
            createdAt = "2026-04-09T00:00:00Z",
            storageMode = "strongbox-or-keystore",
            fingerprint = "fp-a",
            recoveryFingerprint = "rfp-a",
            recoveryPublicJwk = Jwk(kty = "OKP", crv = "Ed25519", x = "AQ", y = ""),
            signingPublicJwk = Jwk(kty = "OKP", crv = "Ed25519", x = "AQ", y = ""),
            encryptionPublicJwk = Jwk(kty = "OKP", crv = "X25519", x = "AQ", y = ""),
            prekeyCreatedAt = "2026-04-09T00:00:00Z",
            prekeyFingerprint = "pfp-a",
            prekeyPublicJwk = Jwk(kty = "OKP", crv = "X25519", x = "AQ", y = ""),
            prekeySignature = "sig-a",
            standardsSignalReady = false,
            standardsMlsReady = false,
        )

        val response = RelayClient(origin = origin).register(identity)

        assertEquals("NTRS-1234", response.user.directoryCode)
        assertEquals(2, testRelay.requests.size)
        assertNull(testRelay.requests[0].headers["x-notrus-pow-token"])
        assertEquals("challenge-token", testRelay.requests[1].headers["x-notrus-pow-token"])
        assertNotNull(testRelay.requests[1].headers["x-notrus-pow-nonce"])
        assertTrue(testRelay.requests[1].body.contains("\"username\":\"alice\""))
    }
}

private class TestRelay : AutoCloseable {
    private val serverSocket = ServerSocket(0)
    private val executor = Executors.newSingleThreadExecutor()
    private val pendingResponses = ArrayDeque<QueuedResponse>()
    private val ready = CountDownLatch(1)
    val requests = mutableListOf<CapturedRequest>()

    val port: Int = serverSocket.localPort

    init {
        executor.execute {
            ready.countDown()
            while (!serverSocket.isClosed) {
                val socket = runCatching { serverSocket.accept() }.getOrNull() ?: break
                socket.use(::respond)
            }
        }
        check(ready.await(5, TimeUnit.SECONDS)) { "Timed out waiting for local test relay." }
    }

    fun enqueue(status: Int, body: String, contentType: String = "application/json") {
        pendingResponses += QueuedResponse(status = status, body = body, contentType = contentType)
    }

    override fun close() {
        runCatching { serverSocket.close() }
        executor.shutdownNow()
    }

    private fun respond(socket: Socket) {
        val input = socket.getInputStream().bufferedReader(StandardCharsets.UTF_8)
        val requestLine = input.readLine() ?: return
        val headerMap = linkedMapOf<String, String>()
        while (true) {
            val line = input.readLine() ?: return
            if (line.isEmpty()) {
                break
            }
            val separator = line.indexOf(':')
            if (separator > 0) {
                val name = line.substring(0, separator).trim().lowercase()
                val value = line.substring(separator + 1).trim()
                headerMap[name] = value
            }
        }

        val contentLength = headerMap["content-length"]?.toIntOrNull() ?: 0
        val body = if (contentLength > 0) {
            val buffer = CharArray(contentLength)
            var offset = 0
            while (offset < contentLength) {
                val read = input.read(buffer, offset, contentLength - offset)
                if (read <= 0) {
                    break
                }
                offset += read
            }
            String(buffer, 0, offset)
        } else {
            ""
        }
        requests += CapturedRequest(
            requestLine = requestLine,
            headers = headerMap,
            body = body,
        )

        val response = pendingResponses.removeFirstOrNull()
            ?: QueuedResponse(status = 500, body = """{"error":"No test response queued."}""")
        val bodyBytes = response.body.toByteArray(StandardCharsets.UTF_8)
        val output = socket.getOutputStream()
        output.write(
            buildString {
                append("HTTP/1.1 ${response.status} ${statusText(response.status)}\r\n")
                append("Content-Type: ${response.contentType}\r\n")
                append("Content-Length: ${bodyBytes.size}\r\n")
                append("Connection: close\r\n")
                append("\r\n")
            }.toByteArray(StandardCharsets.UTF_8)
        )
        output.write(bodyBytes)
        output.flush()
    }

    private fun statusText(status: Int): String =
        when (status) {
            200 -> "OK"
            201 -> "Created"
            400 -> "Bad Request"
            404 -> "Not Found"
            else -> "Test Response"
        }
}

private data class QueuedResponse(
    val status: Int,
    val body: String,
    val contentType: String = "application/json",
)

private data class CapturedRequest(
    val requestLine: String,
    val headers: Map<String, String>,
    val body: String,
)
