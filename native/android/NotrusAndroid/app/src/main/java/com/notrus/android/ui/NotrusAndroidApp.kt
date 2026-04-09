package com.notrus.android.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.Chat
import androidx.compose.material.icons.automirrored.rounded.Send
import androidx.compose.material.icons.rounded.Lock
import androidx.compose.material.icons.rounded.PersonAdd
import androidx.compose.material.icons.rounded.Refresh
import androidx.compose.material.icons.rounded.Search
import androidx.compose.material.icons.rounded.Security
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.FilledIconButton
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import com.notrus.android.model.AppUiState
import com.notrus.android.model.ConversationThread
import com.notrus.android.model.DecryptedMessage
import com.notrus.android.model.RelayUser
import com.notrus.android.model.selectedThread
import com.notrus.android.protocol.ProtocolCatalog
import com.notrus.android.ui.theme.Ember
import com.notrus.android.ui.theme.Fog
import com.notrus.android.ui.theme.Ice
import com.notrus.android.ui.theme.Mint
import com.notrus.android.ui.theme.Night
import com.notrus.android.ui.theme.Ocean
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.time.format.FormatStyle
import java.util.Locale

@Composable
fun NotrusAndroidApp(
    state: AppUiState,
    viewModel: NotrusViewModel,
    activity: FragmentActivity,
) {
    Scaffold { padding ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(
                    brush = Brush.verticalGradient(
                        colors = listOf(Night, Ocean.copy(alpha = 0.9f), Night),
                    ),
                )
                .padding(padding),
        ) {
            when {
                state.vaultLocked -> UnlockView(state = state, onUnlock = { viewModel.unlock(activity) })
                state.profiles.isEmpty() -> OnboardingView(state = state, viewModel = viewModel)
                else -> WorkspaceView(state = state, viewModel = viewModel, activity = activity)
            }
        }
    }
}

@Composable
private fun UnlockView(state: AppUiState, onUnlock: () -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        GlassHero(
            eyebrow = "Device Vault",
            title = "Unlock the Android secure workspace.",
            body = "Profiles are stored in an encrypted local vault. Android Keystore holds the wrap key, and biometrics only reopen local state.",
        )
        Spacer(modifier = Modifier.height(24.dp))
        Button(onClick = onUnlock, shape = RoundedCornerShape(18.dp)) {
            Icon(Icons.Rounded.Lock, contentDescription = null)
            Spacer(modifier = Modifier.size(10.dp))
            Text("Unlock vault")
        }
        state.errorMessage?.let {
            Spacer(modifier = Modifier.height(12.dp))
            Text(text = it, color = Ember)
        }
    }
}

@Composable
private fun OnboardingView(state: AppUiState, viewModel: NotrusViewModel) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(18.dp),
    ) {
        GlassHero(
            eyebrow = "Notrus Android",
            title = "A standards-based Android client is live.",
            body = "Create a device-protected profile, sync the relay, save trusted contacts locally, and open direct Signal chats without the old shell-only limitations.",
        )

        ElevatedCard(
            colors = CardDefaults.elevatedCardColors(containerColor = Fog.copy(alpha = 0.08f)),
            shape = RoundedCornerShape(28.dp),
        ) {
            Column(
                modifier = Modifier.padding(20.dp),
                verticalArrangement = Arrangement.spacedBy(14.dp),
            ) {
                OutlinedTextField(
                    value = state.relayOriginInput,
                    onValueChange = viewModel::updateRelayOrigin,
                    modifier = Modifier.fillMaxWidth(),
                    label = { Text("Relay origin") },
                    singleLine = true,
                )
                OutlinedTextField(
                    value = state.onboardingDisplayName,
                    onValueChange = viewModel::updateOnboardingDisplayName,
                    modifier = Modifier.fillMaxWidth(),
                    label = { Text("Display name") },
                    singleLine = true,
                )
                OutlinedTextField(
                    value = state.onboardingUsername,
                    onValueChange = viewModel::updateOnboardingUsername,
                    modifier = Modifier.fillMaxWidth(),
                    label = { Text("Username") },
                    singleLine = true,
                )
                Button(
                    onClick = viewModel::createProfile,
                    modifier = Modifier.fillMaxWidth(),
                    enabled = !state.isBusy,
                    shape = RoundedCornerShape(18.dp),
                ) {
                    if (state.isBusy) {
                        CircularProgressIndicator(modifier = Modifier.size(18.dp), strokeWidth = 2.dp)
                    } else {
                        Icon(Icons.Rounded.Security, contentDescription = null)
                    }
                    Spacer(modifier = Modifier.size(10.dp))
                    Text("Create Android profile")
                }
                Text(text = state.statusMessage, color = Fog.copy(alpha = 0.8f))
                state.errorMessage?.let { Text(text = it, color = Ember) }
            }
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun WorkspaceView(
    state: AppUiState,
    viewModel: NotrusViewModel,
    activity: FragmentActivity,
) {
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(18.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        item {
            GlassHero(
                eyebrow = "Native Android",
                title = state.currentIdentity?.displayName ?: "Notrus Android",
                body = state.statusMessage,
            )
        }

        item {
            if (state.isBusy) {
                LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
            }
        }

        item {
            ElevatedCard(
                colors = CardDefaults.elevatedCardColors(containerColor = Fog.copy(alpha = 0.08f)),
                shape = RoundedCornerShape(26.dp),
            ) {
                Column(
                    modifier = Modifier.padding(18.dp),
                    verticalArrangement = Arrangement.spacedBy(14.dp),
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                            Text("Profile ring", style = MaterialTheme.typography.titleMedium)
                            state.currentIdentity?.let { identity ->
                                Text("@${identity.username}", style = MaterialTheme.typography.bodyMedium, color = Fog)
                                Text(
                                    identity.fingerprint,
                                    style = MaterialTheme.typography.labelMedium,
                                    color = Ice,
                                )
                            } ?: Text(
                                "No fingerprint",
                                style = MaterialTheme.typography.labelMedium,
                                color = Ice,
                            )
                        }
                        FilledIconButton(onClick = viewModel::refresh) {
                            Icon(Icons.Rounded.Refresh, contentDescription = null)
                        }
                    }

                    FlowRow(
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        state.profiles.forEach { profile ->
                            FilterChip(
                                selected = state.currentIdentity?.id == profile.id,
                                onClick = { viewModel.switchProfile(profile.id) },
                                label = { Text(profile.username) },
                            )
                        }
                    }

                    HorizontalDivider(color = Fog.copy(alpha = 0.08f))

                    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text("Invite code", style = MaterialTheme.typography.titleMedium)
                        Text(
                            text = state.currentDirectoryCode ?: "Pending relay registration",
                            style = MaterialTheme.typography.labelMedium,
                            color = if (state.currentDirectoryCode == null) Fog.copy(alpha = 0.7f) else Ice,
                        )
                    }

                    state.currentDevice?.let { device ->
                        Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                            Text("This device", style = MaterialTheme.typography.titleMedium)
                            Text(device.label, style = MaterialTheme.typography.bodyMedium, color = Fog)
                            Text(device.id, style = MaterialTheme.typography.labelSmall, color = Ice)
                        }
                    }

                    state.integrityReport?.let { report ->
                        FlowRow(
                            horizontalArrangement = Arrangement.spacedBy(10.dp),
                            verticalArrangement = Arrangement.spacedBy(10.dp),
                        ) {
                            StatusPill(label = "Risk ${report.riskLevel.uppercase()}", tone = if (report.riskLevel == "low") Mint else Ember)
                            StatusPill(label = report.codeSignatureStatus, tone = Ice)
                            StatusPill(label = report.deviceCheckStatus, tone = Mint)
                        }
                    }

                    Text("Relay", style = MaterialTheme.typography.titleMedium)
                    OutlinedTextField(
                        value = state.relayOriginInput,
                        onValueChange = viewModel::updateRelayOrigin,
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true,
                        label = { Text("Relay origin") },
                    )
                    OutlinedTextField(
                        value = state.witnessOriginsInput,
                        onValueChange = viewModel::updateWitnessOrigins,
                        modifier = Modifier.fillMaxWidth(),
                        label = { Text("Witness origins (comma separated)") },
                    )

                    state.relayHealth?.let { health ->
                        FlowRow(
                            horizontalArrangement = Arrangement.spacedBy(10.dp),
                            verticalArrangement = Arrangement.spacedBy(10.dp),
                        ) {
                            StatusPill(label = health.protocolLabel, tone = Ice)
                            StatusPill(label = health.transportLabel.uppercase(), tone = Mint)
                            if (health.attestationConfigured == true) {
                                StatusPill(
                                    label = if (health.attestationRequired == true) "Attestation required" else "Attestation ready",
                                    tone = if (health.attestationRequired == true) Mint else Ice,
                                )
                            }
                        }
                        health.directoryDiscoveryMode?.let { mode ->
                            Text(
                                text = if (mode == "exact-username-or-invite" || mode == "username-or-invite") {
                                    "Discovery allows username or invite-code lookup."
                                } else {
                                    "Discovery allows explicit search."
                                },
                                style = MaterialTheme.typography.bodyMedium,
                                color = Fog.copy(alpha = 0.72f),
                            )
                        }
                        Text(
                            text = health.protocolNote,
                            style = MaterialTheme.typography.bodyMedium,
                            color = Fog.copy(alpha = 0.78f),
                        )
                    }

                    FlowRow(
                        horizontalArrangement = Arrangement.spacedBy(10.dp),
                        verticalArrangement = Arrangement.spacedBy(10.dp),
                    ) {
                        StatusPill(
                            label = if (state.transparency.chainValid) "Transparency verified" else "Transparency review",
                            tone = if (state.transparency.chainValid) Mint else Ember,
                        )
                        StatusPill(
                            label = "${state.transparency.entries.size} entries",
                            tone = Ice,
                        )
                        state.transparency.head?.let { head ->
                            StatusPill(label = head.take(10), tone = Fog)
                        }
                    }
                    if (state.transparency.warnings.isNotEmpty()) {
                        Text(
                            state.transparency.warnings.first(),
                            color = Ember,
                            style = MaterialTheme.typography.bodySmall,
                        )
                        if (state.transparencyResetAvailable) {
                            Text(
                                "This Android device still has an older pinned relay head or signer. Reset the local transparency trust once, then sync again.",
                                color = Fog.copy(alpha = 0.76f),
                                style = MaterialTheme.typography.bodySmall,
                            )
                            Button(
                                onClick = viewModel::resetTransparencyTrust,
                                enabled = !state.isBusy,
                                shape = RoundedCornerShape(16.dp),
                            ) {
                                Text("Reset transparency trust")
                            }
                        }
                    }
                }
            }
        }

        item {
            Card(
                colors = CardDefaults.cardColors(containerColor = Fog.copy(alpha = 0.05f)),
                shape = RoundedCornerShape(24.dp),
            ) {
                Column(
                    modifier = Modifier.padding(18.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    Text("Add another profile", style = MaterialTheme.typography.titleMedium)
                    Text(
                        "Create a second Android identity in the same encrypted vault so you can switch profiles and test contact flows locally.",
                        color = Fog.copy(alpha = 0.72f),
                    )
                    OutlinedTextField(
                        value = state.onboardingDisplayName,
                        onValueChange = viewModel::updateOnboardingDisplayName,
                        modifier = Modifier.fillMaxWidth(),
                        label = { Text("New display name") },
                        singleLine = true,
                    )
                    OutlinedTextField(
                        value = state.onboardingUsername,
                        onValueChange = viewModel::updateOnboardingUsername,
                        modifier = Modifier.fillMaxWidth(),
                        label = { Text("New username") },
                        singleLine = true,
                    )
                    Button(
                        onClick = viewModel::createProfile,
                        enabled = !state.isBusy,
                        shape = RoundedCornerShape(18.dp),
                    ) {
                        Icon(Icons.Rounded.PersonAdd, contentDescription = null)
                        Spacer(modifier = Modifier.size(10.dp))
                        Text("Create and switch")
                    }
                }
            }
        }

        item {
            Card(
                colors = CardDefaults.cardColors(containerColor = Fog.copy(alpha = 0.05f)),
                shape = RoundedCornerShape(24.dp),
            ) {
                Column(
                    modifier = Modifier.padding(18.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp),
                ) {
                    Text("Protocol core status", style = MaterialTheme.typography.titleMedium)
                    Text(
                        state.protocolEngineMessage,
                        style = MaterialTheme.typography.bodyMedium,
                        color = Fog.copy(alpha = 0.82f),
                    )
                    Text(
                        "The packaged alpha build now targets a signed release artifact for device testing.",
                        style = MaterialTheme.typography.bodySmall,
                        color = Fog.copy(alpha = 0.68f),
                    )
                }
            }
        }

        item {
            Card(
                colors = CardDefaults.cardColors(containerColor = Fog.copy(alpha = 0.05f)),
                shape = RoundedCornerShape(24.dp),
            ) {
                Column(
                    modifier = Modifier.padding(18.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    Text("Linked devices", style = MaterialTheme.typography.titleMedium)
                    Text(
                        "Each device keeps a separate device-management key and can be revoked without changing conversation membership.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = Fog.copy(alpha = 0.76f),
                    )
                    if (state.linkedDevices.isEmpty()) {
                        Text("No linked devices registered yet.", color = Fog.copy(alpha = 0.7f))
                    } else {
                        state.linkedDevices.forEach { device ->
                            ElevatedCard(
                                colors = CardDefaults.elevatedCardColors(containerColor = Fog.copy(alpha = 0.08f)),
                                shape = RoundedCornerShape(20.dp),
                            ) {
                                Column(
                                    modifier = Modifier.padding(14.dp),
                                    verticalArrangement = Arrangement.spacedBy(8.dp),
                                ) {
                                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                                        Text(
                                            device.label,
                                            style = MaterialTheme.typography.titleSmall,
                                            color = Fog,
                                            maxLines = 2,
                                            overflow = TextOverflow.Ellipsis,
                                        )
                                        Text(
                                            "${device.platform} · ${device.id}",
                                            style = MaterialTheme.typography.labelSmall,
                                            color = Ice,
                                            maxLines = 1,
                                            overflow = TextOverflow.Ellipsis,
                                        )
                                        FlowRow(
                                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                                            verticalArrangement = Arrangement.spacedBy(8.dp),
                                        ) {
                                            if (device.current) {
                                                StatusPill(label = "This device", tone = Ice)
                                            }
                                            if (device.revokedAt != null) {
                                                StatusPill(label = "Revoked", tone = Ember)
                                            }
                                            device.attestationStatus?.let { status ->
                                                StatusPill(label = status.replace('-', ' '), tone = Mint)
                                            }
                                        }
                                    }
                                    Text(
                                        "Risk ${device.riskLevel.uppercase()} · Updated ${formatConversationTimestamp(device.updatedAt)}",
                                        color = Fog.copy(alpha = 0.7f),
                                        style = MaterialTheme.typography.bodySmall,
                                    )
                                    device.attestationNote?.let { note ->
                                        Text(note, color = Fog.copy(alpha = 0.65f), style = MaterialTheme.typography.bodySmall)
                                    }
                                    if (!device.current && device.revokedAt == null) {
                                        TextButton(onClick = { viewModel.revokeLinkedDevice(activity, device.id) }) {
                                            Text("Revoke linked device")
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        item {
            Card(
                colors = CardDefaults.cardColors(containerColor = Fog.copy(alpha = 0.05f)),
                shape = RoundedCornerShape(24.dp),
            ) {
                Column(
                    modifier = Modifier.padding(18.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    Text("Directory", style = MaterialTheme.typography.titleMedium)
                    Row(horizontalArrangement = Arrangement.spacedBy(10.dp), verticalAlignment = Alignment.CenterVertically) {
                        OutlinedTextField(
                            value = state.directoryQuery,
                            onValueChange = viewModel::updateDirectoryQuery,
                            modifier = Modifier.weight(1f),
                            label = { Text("Lookup username or invite code") },
                            singleLine = true,
                        )
                        FilledIconButton(onClick = viewModel::searchDirectory) {
                            Icon(Icons.Rounded.Search, contentDescription = null)
                        }
                    }
                    Text(
                        "Search by username or invite code, then save the contact explicitly into the local Android vault.",
                        color = Fog.copy(alpha = 0.72f),
                    )
                    if (state.directoryResults.isEmpty()) {
                        Text(
                            if (state.directoryQuery.isBlank()) "No search results yet." else "No matching relay users found.",
                            color = Fog.copy(alpha = 0.7f),
                        )
                    } else {
                        state.directoryResults.forEach { user ->
                            ContactRow(
                                user = user,
                                onSave = { viewModel.saveContact(user.id) },
                                onOpenChat = { viewModel.openDirectChat(activity, user.id) },
                                canOpenChat = user.signalBundle != null,
                            )
                        }
                    }
                }
            }
        }

        item {
            Card(
                colors = CardDefaults.cardColors(containerColor = Fog.copy(alpha = 0.05f)),
                shape = RoundedCornerShape(24.dp),
            ) {
                Column(
                    modifier = Modifier.padding(18.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    Text("Saved contacts", style = MaterialTheme.typography.titleMedium)
                    if (state.contacts.isEmpty()) {
                        Text("Save contacts from the directory to keep them in the local Android vault.", color = Fog.copy(alpha = 0.7f))
                    } else {
                        state.contacts.forEach { user ->
                            ContactRow(
                                user = user,
                                onSave = null,
                                onOpenChat = { viewModel.openDirectChat(activity, user.id) },
                                canOpenChat = user.signalBundle != null,
                            )
                        }
                    }
                }
            }
        }

        item {
            Text("Threads", style = MaterialTheme.typography.headlineMedium, color = Fog)
        }

        if (state.threads.isEmpty()) {
            item {
                Text(
                    "No threads yet. Save a contact, then open a direct chat to create the first Android standards conversation.",
                    color = Fog.copy(alpha = 0.72f),
                )
            }
        } else {
            items(state.threads, key = { it.id }) { thread ->
                ThreadCard(
                    thread = thread,
                    selected = thread.id == state.selectedThreadId,
                    onClick = { viewModel.selectThread(thread.id) },
                )
            }
        }

        item {
            Card(
                colors = CardDefaults.cardColors(containerColor = Fog.copy(alpha = 0.05f)),
                shape = RoundedCornerShape(24.dp),
            ) {
                Column(
                    modifier = Modifier.padding(18.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    Text("Conversation", style = MaterialTheme.typography.titleMedium)
                    val selected = state.selectedThread
                    if (selected == null) {
                        Text("Pick a thread to inspect its secure transcript and send from Android.", color = Fog.copy(alpha = 0.72f))
                    } else {
                        Text(
                            text = selected.title.ifBlank { "Secure conversation" },
                            style = MaterialTheme.typography.titleLarge,
                            color = Fog,
                            maxLines = 2,
                            overflow = TextOverflow.Ellipsis,
                        )
                        FlowRow(
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                            verticalArrangement = Arrangement.spacedBy(8.dp),
                        ) {
                            StatusPill(label = selected.protocolLabel, tone = Ice)
                            StatusPill(label = if (selected.supported) "Send ready" else "Read only", tone = if (selected.supported) Mint else Ember)
                            StatusPill(label = "${selected.messageCount} msgs", tone = Fog)
                            if (selected.attachmentCount > 0) {
                                StatusPill(label = attachmentCountLabel(selected.attachmentCount), tone = Ice)
                            }
                        }
                        Text(
                            text = participantsSummary(selected, state.currentIdentity?.id),
                            color = Fog.copy(alpha = 0.82f),
                            style = MaterialTheme.typography.bodyMedium,
                        )
                        Text(
                            text = "Updated ${formatConversationTimestamp(selected.lastActivityAt)}",
                            color = Fog.copy(alpha = 0.68f),
                            style = MaterialTheme.typography.bodySmall,
                        )
                        selected.warning?.let { Text(it, color = Ember) }

                        if (selected.messages.isEmpty()) {
                            Text("No messages in this thread yet.", color = Fog.copy(alpha = 0.72f))
                        } else {
                            selected.messages.takeLast(12).forEach { message ->
                                MessageBubble(message = message, isLocal = message.senderId == state.currentIdentity?.id)
                            }
                        }

                        OutlinedTextField(
                            value = state.draftText,
                            onValueChange = viewModel::updateDraftText,
                            modifier = Modifier.fillMaxWidth(),
                            label = { Text("Message") },
                            enabled = selected.supported,
                        )

                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.End,
                        ) {
                            Button(
                                onClick = { viewModel.sendSelectedMessage(activity) },
                                enabled = selected.supported && state.draftText.isNotBlank() && !state.isBusy,
                                shape = RoundedCornerShape(18.dp),
                            ) {
                                Icon(Icons.AutoMirrored.Rounded.Send, contentDescription = null)
                                Spacer(modifier = Modifier.size(10.dp))
                                Text(if (selected.supported) "Send encrypted message" else "Unsupported on Android")
                            }
                        }
                    }
                }
            }
        }

        item {
            state.errorMessage?.let { Text(text = it, color = Ember) }
        }
    }
}

@Composable
private fun GlassHero(eyebrow: String, title: String, body: String) {
    ElevatedCard(
        colors = CardDefaults.elevatedCardColors(containerColor = Color.Transparent),
        shape = RoundedCornerShape(32.dp),
    ) {
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .background(
                    brush = Brush.linearGradient(
                        colors = listOf(Ice.copy(alpha = 0.18f), Mint.copy(alpha = 0.12f), Color.White.copy(alpha = 0.04f)),
                    ),
                    shape = RoundedCornerShape(32.dp),
                )
                .padding(24.dp),
        ) {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(
                    text = eyebrow.uppercase(),
                    style = MaterialTheme.typography.labelMedium,
                    color = Ice,
                )
                Text(text = title, style = MaterialTheme.typography.headlineLarge, color = Fog)
                Text(text = body, style = MaterialTheme.typography.bodyLarge, color = Fog.copy(alpha = 0.86f))
            }
        }
    }
}

@Composable
private fun StatusPill(label: String, tone: Color) {
    Surface(
        shape = CircleShape,
        color = tone.copy(alpha = 0.18f),
    ) {
        Text(
            text = label,
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
            style = MaterialTheme.typography.labelMedium,
            color = tone,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
    }
}

@Composable
private fun ContactRow(
    user: RelayUser,
    onSave: (() -> Unit)?,
    onOpenChat: () -> Unit,
    canOpenChat: Boolean,
) {
    ElevatedCard(
        colors = CardDefaults.elevatedCardColors(containerColor = Fog.copy(alpha = 0.08f)),
        shape = RoundedCornerShape(20.dp),
    ) {
        Column(
            modifier = Modifier.padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(user.displayName, color = Fog, fontWeight = FontWeight.SemiBold)
                    Text("@${user.username}", color = Fog.copy(alpha = 0.72f))
                }
                Text(
                    user.fingerprint.take(19),
                    style = MaterialTheme.typography.labelMedium,
                    color = Ice,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                if (onSave != null) {
                    TextButton(onClick = onSave) {
                        Icon(Icons.Rounded.PersonAdd, contentDescription = null)
                        Spacer(modifier = Modifier.size(8.dp))
                        Text("Save")
                    }
                }
                Button(
                    onClick = onOpenChat,
                    enabled = canOpenChat,
                    shape = RoundedCornerShape(16.dp),
                ) {
                    Icon(Icons.AutoMirrored.Rounded.Chat, contentDescription = null)
                    Spacer(modifier = Modifier.size(8.dp))
                    Text(if (canOpenChat) "Open direct chat" else "Signal bundle missing")
                }
            }
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun ThreadCard(thread: ConversationThread, selected: Boolean, onClick: () -> Unit) {
    ElevatedCard(
        onClick = onClick,
        colors = CardDefaults.elevatedCardColors(
            containerColor = if (selected) Ice.copy(alpha = 0.14f) else Fog.copy(alpha = 0.05f),
        ),
        shape = RoundedCornerShape(24.dp),
    ) {
        Column(
            modifier = Modifier.padding(18.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    text = thread.title.ifBlank { thread.id },
                    color = Fog,
                    style = MaterialTheme.typography.titleMedium,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                StatusPill(
                    label = if (thread.supported) "Ready" else "Read only",
                    tone = if (thread.protocol.startsWith("mls") || thread.protocol.startsWith("signal")) Mint else Ember,
                )
            }
            FlowRow(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                StatusPill(label = thread.protocolLabel, tone = Ice)
                if (thread.attachmentCount > 0) {
                    StatusPill(label = attachmentCountLabel(thread.attachmentCount), tone = Fog)
                }
            }
            Text(
                text = participantsSummary(thread, null),
                color = Fog.copy(alpha = 0.82f),
                style = MaterialTheme.typography.bodyMedium,
            )
            Text(
                text = "${thread.messageCount} messages · Updated ${formatConversationTimestamp(thread.lastActivityAt)}",
                color = Fog.copy(alpha = 0.65f),
                style = MaterialTheme.typography.bodySmall,
            )
            thread.warning?.let {
                Text(
                    text = it,
                    color = Ember,
                    style = MaterialTheme.typography.bodySmall,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }
    }
}

@Composable
private fun MessageBubble(message: DecryptedMessage, isLocal: Boolean) {
    Column(
        modifier = Modifier.fillMaxWidth(),
        horizontalAlignment = if (isLocal) Alignment.End else Alignment.Start,
    ) {
        ElevatedCard(
            modifier = Modifier.fillMaxWidth(0.88f),
            colors = CardDefaults.elevatedCardColors(
                containerColor = when {
                    message.status != "ok" -> Ember.copy(alpha = 0.14f)
                    isLocal -> Ice.copy(alpha = 0.14f)
                    else -> Fog.copy(alpha = 0.08f)
                },
            ),
            shape = RoundedCornerShape(20.dp),
        ) {
            Column(
                modifier = Modifier.padding(14.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        text = if (isLocal) "You" else message.senderName,
                        style = MaterialTheme.typography.labelLarge,
                        color = if (isLocal) Ice else Fog.copy(alpha = 0.88f),
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                    Text(
                        text = formatConversationTimestamp(message.createdAt),
                        color = Fog.copy(alpha = 0.58f),
                        style = MaterialTheme.typography.labelSmall,
                    )
                }

                Text(
                    text = message.body,
                    color = Fog,
                    style = MaterialTheme.typography.bodyLarge,
                )

                if (message.attachments.isNotEmpty()) {
                    Surface(
                        color = Color.White.copy(alpha = 0.06f),
                        shape = RoundedCornerShape(14.dp),
                    ) {
                        Column(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(horizontal = 12.dp, vertical = 10.dp),
                            verticalArrangement = Arrangement.spacedBy(4.dp),
                        ) {
                            Text(
                                text = attachmentCountLabel(message.attachments.size),
                                style = MaterialTheme.typography.labelLarge,
                                color = Ice,
                            )
                            Text(
                                text = message.attachments.joinToString(", ") { it.fileName },
                                style = MaterialTheme.typography.bodySmall,
                                color = Fog.copy(alpha = 0.78f),
                                maxLines = 2,
                                overflow = TextOverflow.Ellipsis,
                            )
                        }
                    }
                }

                messageStatusLabel(message.status)?.let { status ->
                    StatusPill(label = status, tone = Ember)
                }
            }
        }
    }
}

private fun participantsSummary(thread: ConversationThread, currentUserId: String?): String {
    val remoteNames = thread.participants
        .filter { participant -> currentUserId == null || participant.id != currentUserId }
        .map { participant -> participant.displayName.ifBlank { participant.username } }
    return when {
        remoteNames.isEmpty() -> "${thread.participants.size} participants"
        remoteNames.size == 1 -> remoteNames.first()
        remoteNames.size == 2 -> remoteNames.joinToString(" and ")
        else -> remoteNames.take(2).joinToString(", ") + " +${remoteNames.size - 2} more"
    }
}

private fun attachmentCountLabel(count: Int): String =
    if (count == 1) "1 attachment" else "$count attachments"

private fun messageStatusLabel(status: String): String? =
    when (status) {
        "ok" -> null
        "invalid" -> "Needs review"
        "unsupported" -> "Read only on Android"
        "missing-local-state" -> "Plaintext unavailable here"
        else -> status.replace('-', ' ').replaceFirstChar { if (it.isLowerCase()) it.titlecase(Locale.getDefault()) else it.toString() }
    }

private fun formatConversationTimestamp(raw: String): String {
    val zoneId = ZoneId.systemDefault()
    return runCatching {
        val instant = Instant.parse(raw)
        val zoned = instant.atZone(zoneId)
        val now = Instant.now().atZone(zoneId)
        when {
            zoned.toLocalDate() == now.toLocalDate() ->
                DateTimeFormatter.ofLocalizedTime(FormatStyle.SHORT).format(zoned)
            zoned.year == now.year ->
                DateTimeFormatter.ofPattern("d MMM, HH:mm", Locale.getDefault()).format(zoned)
            else ->
                DateTimeFormatter.ofPattern("d MMM yyyy, HH:mm", Locale.getDefault()).format(zoned)
        }
    }.getOrElse { raw }
}
