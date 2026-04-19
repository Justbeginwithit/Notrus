package com.notrus.android.relay

import androidx.test.ext.junit.runners.AndroidJUnit4
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

        val users = RelayClient(origin = origin).searchDirectory("user-a", "ABCD-1234")

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

        val users = RelayClient(origin = origin).searchDirectory("user-a", "bob")

        assertEquals(1, users.size)
        val bundle = users.first().signalBundle
        assertNotNull(bundle)
        assertEquals(3719580524L.toInt(), bundle?.registrationId)
    }

    @Test
    fun searchDirectorySurfacesPlainTextServerErrors() = runBlocking {
        testRelay.enqueue(status = 400, body = "The invite code is invalid.", contentType = "text/plain; charset=utf-8")

        val error = runCatching {
            RelayClient(origin = origin).searchDirectory("user-a", "invalid")
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

        val threadId = RelayClient(origin = origin).createDirectThread("user-a", "user-b")

        assertEquals("thread-direct-1", threadId)
    }

    @Test
    fun syncTreatsJsonNullTransparencyPreviousHashAsMissing() = runBlocking {
        testRelay.enqueue(
            status = 200,
            body = JSONObject()
                .put("entryCount", 1)
                .put("transparencyHead", "head-1")
                .put("transparencySignature", "sig-1")
                .put(
                    "transparencySigner",
                    JSONObject()
                        .put("algorithm", "ed25519")
                        .put("keyId", "signer-1")
                        .put("publicKeyRaw", "raw")
                        .put("publicKeySpki", "spki")
                )
                .put(
                    "transparencyEntries",
                    JSONArray().put(
                        JSONObject()
                            .put("createdAt", "2026-04-09T00:00:00Z")
                            .put("entryHash", "entry-1")
                            .put("fingerprint", "fp-1")
                            .put("kind", "identity-created")
                            .put("prekeyFingerprint", JSONObject.NULL)
                            .put("previousHash", JSONObject.NULL)
                            .put("sequence", 1)
                            .put("userId", "user-a")
                            .put("username", "alice")
                    )
                )
                .put("users", JSONArray())
                .put("threads", JSONArray())
                .put("deviceEvents", JSONArray())
                .put("devices", JSONArray())
                .toString()
        )

        val sync = RelayClient(origin = origin).sync("user-a")

        assertEquals(1, sync.transparencyEntries.size)
        assertNull(sync.transparencyEntries.first().previousHash)
        assertNull(sync.transparencyEntries.first().prekeyFingerprint)
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

        val identity = com.notrus.android.model.LocalIdentity(
            id = "user-a",
            username = "alice",
            displayName = "Alice",
            createdAt = "2026-04-09T00:00:00Z",
            storageMode = "strongbox-or-keystore",
            fingerprint = "fp-a",
            recoveryFingerprint = "rfp-a",
            recoveryPublicJwk = com.notrus.android.model.Jwk(kty = "OKP", crv = "Ed25519", x = "AQ", y = ""),
            signingPublicJwk = com.notrus.android.model.Jwk(kty = "OKP", crv = "Ed25519", x = "AQ", y = ""),
            encryptionPublicJwk = com.notrus.android.model.Jwk(kty = "OKP", crv = "X25519", x = "AQ", y = ""),
            prekeyCreatedAt = "2026-04-09T00:00:00Z",
            prekeyFingerprint = "pfp-a",
            prekeyPublicJwk = com.notrus.android.model.Jwk(kty = "OKP", crv = "X25519", x = "AQ", y = ""),
            prekeySignature = "sig-a",
            standardsSignalReady = false,
            standardsMlsReady = false,
        )

        val user = RelayClient(origin = origin).register(identity)

        assertEquals("NTRS-1234", user.directoryCode)
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
        ready.await(5, TimeUnit.SECONDS)
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
