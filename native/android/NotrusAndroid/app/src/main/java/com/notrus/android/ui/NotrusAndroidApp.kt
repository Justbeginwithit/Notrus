@file:OptIn(androidx.compose.foundation.layout.ExperimentalLayoutApi::class)

package com.notrus.android.ui

import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateContentSize
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.animation.slideInHorizontally
import androidx.compose.animation.slideOutHorizontally
import androidx.compose.animation.togetherWith
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.ArrowBack
import androidx.compose.material.icons.automirrored.rounded.Chat
import androidx.compose.material.icons.automirrored.rounded.Send
import androidx.compose.material.icons.rounded.CheckCircle
import androidx.compose.material.icons.rounded.Download
import androidx.compose.material.icons.rounded.Info
import androidx.compose.material.icons.rounded.Lock
import androidx.compose.material.icons.rounded.PersonAdd
import androidx.compose.material.icons.rounded.Refresh
import androidx.compose.material.icons.rounded.Search
import androidx.compose.material.icons.rounded.Security
import androidx.compose.material.icons.rounded.Settings
import androidx.compose.material.icons.rounded.Upload
import androidx.compose.material.icons.rounded.WarningAmber
import androidx.compose.material3.BottomAppBar
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledIconButton
import androidx.compose.material3.IconButtonDefaults
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationRail
import androidx.compose.material3.NavigationRailItem
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.graphics.lerp
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import com.notrus.android.model.AppUiState
import com.notrus.android.model.ConversationThread
import com.notrus.android.model.DecryptedMessage
import com.notrus.android.model.DeviceInventoryAlias
import com.notrus.android.model.DeviceInventoryProfile
import com.notrus.android.model.RelayLinkedDevice
import com.notrus.android.model.RelayUser
import com.notrus.android.model.selectedThread
import com.notrus.android.ui.theme.NotrusColorTheme
import com.notrus.android.ui.theme.NotrusThemeMode
import kotlinx.coroutines.delay
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.time.format.FormatStyle
import java.util.Locale

private const val DefaultStatusMessage = "Android native client ready."
private const val MinimumDirectorySearchLength = 3
private val PanelShape = RoundedCornerShape(26.dp)
private val RowShape = RoundedCornerShape(24.dp)
private val BubbleShape = RoundedCornerShape(24.dp)

private enum class WorkspaceDestination(
    val label: String,
    val icon: ImageVector,
) {
    Chats("Chats", Icons.AutoMirrored.Rounded.Chat),
    Contacts("Contacts", Icons.Rounded.Search),
    Security("Security", Icons.Rounded.Security),
    Settings("Settings", Icons.Rounded.Settings),
}

private enum class BannerTone {
    Info,
    Warning,
    Success,
}

@Composable
fun NotrusAndroidApp(
    state: AppUiState,
    viewModel: NotrusViewModel,
    activity: FragmentActivity,
) {
    val importArchiveLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument(),
    ) { uri ->
        uri?.let { viewModel.importProfile(activity, it) }
    }
    val exportArchiveLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("application/json"),
    ) { uri ->
        uri?.let { viewModel.exportCurrentProfile(activity, it) }
    }

    var destination by rememberSaveable { mutableStateOf(WorkspaceDestination.Chats) }
    var chatQuery by rememberSaveable { mutableStateOf("") }

    LaunchedEffect(state.statusMessage, state.isBusy) {
        val message = state.statusMessage
        if (!state.isBusy && message != DefaultStatusMessage) {
            delay(4200)
            viewModel.dismissStatusMessage(message)
        }
    }

    LaunchedEffect(state.errorMessage) {
        val message = state.errorMessage
        if (!message.isNullOrBlank()) {
            delay(5200)
            viewModel.dismissErrorMessage(message)
        }
    }

    BoxWithConstraints(modifier = Modifier.fillMaxSize()) {
        val wideLayout = maxWidth >= 900.dp
        val showChatDetail = destination == WorkspaceDestination.Chats && !wideLayout && state.selectedThread != null

        BackHandler(enabled = showChatDetail) {
            viewModel.clearSelectedThread()
        }

        when {
            state.vaultLocked -> UnlockView(state = state, onUnlock = { viewModel.unlock(activity) })
            state.profiles.isEmpty() -> OnboardingView(
                state = state,
                viewModel = viewModel,
                onImportArchive = {
                    importArchiveLauncher.launch(arrayOf("application/json", "text/*", "*/*"))
                },
            )
            else -> WorkspaceScaffold(
                state = state,
                viewModel = viewModel,
                activity = activity,
                enhancedVisuals = state.visualEffectsEnabled,
                destination = destination,
                onDestinationChange = { destination = it },
                wideLayout = wideLayout,
                chatQuery = chatQuery,
                onChatQueryChange = { chatQuery = it },
                onExportArchive = {
                    val username = state.currentIdentity?.username ?: "android"
                    exportArchiveLauncher.launch("notrus-$username-recovery.json")
                },
                onImportArchive = {
                    importArchiveLauncher.launch(arrayOf("application/json", "text/*", "*/*"))
                },
            )
        }
    }
}

@Composable
private fun UnlockView(
    state: AppUiState,
    onUnlock: () -> Unit,
) {
    Surface(
        modifier = Modifier.fillMaxSize(),
        color = MaterialTheme.colorScheme.background,
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 24.dp, vertical = 32.dp),
            verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Surface(
                shape = CircleShape,
                color = MaterialTheme.colorScheme.primaryContainer,
            ) {
                Icon(
                    imageVector = Icons.Rounded.Lock,
                    contentDescription = null,
                    modifier = Modifier.padding(18.dp),
                    tint = MaterialTheme.colorScheme.onPrimaryContainer,
                )
            }
            Spacer(modifier = Modifier.height(20.dp))
            Text(
                text = "Unlock local vault",
                style = MaterialTheme.typography.headlineMedium,
                color = MaterialTheme.colorScheme.onBackground,
                textAlign = TextAlign.Center,
            )
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                text = "Use device authentication to reopen the encrypted workspace on this Android device.",
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center,
            )
            Spacer(modifier = Modifier.height(24.dp))
            Button(
                onClick = onUnlock,
                shape = RoundedCornerShape(18.dp),
            ) {
                Text("Unlock")
            }
            state.errorMessage?.let {
                Spacer(modifier = Modifier.height(16.dp))
                StatusBanner(
                    message = it,
                    tone = BannerTone.Warning,
                )
            }
        }
    }
}

@Composable
private fun OnboardingView(
    state: AppUiState,
    viewModel: NotrusViewModel,
    onImportArchive: () -> Unit,
) {
    val scrollState = rememberScrollState()
    Surface(
        modifier = Modifier.fillMaxSize(),
        color = MaterialTheme.colorScheme.background,
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(scrollState)
                .padding(horizontal = 20.dp, vertical = 24.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Text(
                text = "Set up Notrus on Android",
                style = MaterialTheme.typography.headlineMedium,
                color = MaterialTheme.colorScheme.onBackground,
            )
            Text(
                text = "Create a device-protected profile or import a recovery archive. Direct chats are the stable cross-platform path in the current alpha.",
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            if (state.isBusy) {
                AppLoadingIndicator(
                    enhanced = state.visualEffectsEnabled,
                    modifier = Modifier.fillMaxWidth(),
                )
            }

            state.errorMessage?.let {
                StatusBanner(message = it, tone = BannerTone.Warning)
            }

            if (state.statusMessage != DefaultStatusMessage) {
                StatusBanner(message = state.statusMessage, tone = BannerTone.Info)
            }

            SectionCard(
                title = "Create profile",
                subtitle = "The local vault is encrypted. Android Keystore protects the wrap key, and the app can reopen local state with device authentication.",
            ) {
                OutlinedTextField(
                    value = state.relayOriginInput,
                    onValueChange = viewModel::updateRelayOrigin,
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    label = { Text("Relay origin") },
                )
                OutlinedTextField(
                    value = state.onboardingDisplayName,
                    onValueChange = viewModel::updateOnboardingDisplayName,
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    label = { Text("Display name") },
                )
                OutlinedTextField(
                    value = state.onboardingUsername,
                    onValueChange = viewModel::updateOnboardingUsername,
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    label = { Text("Username") },
                )
                Button(
                    onClick = viewModel::createProfile,
                    enabled = !state.isBusy,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(18.dp),
                ) {
                    if (state.isBusy) {
                        CircularProgressIndicator(modifier = Modifier.size(18.dp), strokeWidth = 2.dp)
                    } else {
                        Text("Create Android profile")
                    }
                }
            }

            SectionCard(
                title = "Import recovery archive",
                subtitle = "Same-platform recovery import is the supported path. Android to macOS recovery import still has known issues and is not the stable migration path yet.",
            ) {
                OutlinedTextField(
                    value = state.importPassphrase,
                    onValueChange = viewModel::updateImportPassphrase,
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    label = { Text("Import passphrase") },
                )
                FilledTonalButton(
                    onClick = onImportArchive,
                    enabled = !state.isBusy,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(18.dp),
                ) {
                    Icon(Icons.Rounded.Upload, contentDescription = null)
                    Spacer(modifier = Modifier.width(10.dp))
                    Text("Choose archive")
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun WorkspaceScaffold(
    state: AppUiState,
    viewModel: NotrusViewModel,
    activity: FragmentActivity,
    enhancedVisuals: Boolean,
    destination: WorkspaceDestination,
    onDestinationChange: (WorkspaceDestination) -> Unit,
    wideLayout: Boolean,
    chatQuery: String,
    onChatQueryChange: (String) -> Unit,
    onExportArchive: () -> Unit,
    onImportArchive: () -> Unit,
) {
    val selectedThread = state.selectedThread
    val showConversationDetail = destination == WorkspaceDestination.Chats && !wideLayout && selectedThread != null

    Scaffold(
        containerColor = Color.Transparent,
        contentWindowInsets = WindowInsets(0.dp),
        topBar = {
            WorkspaceTopBar(
                state = state,
                showConversationDetail = showConversationDetail,
                selectedThread = selectedThread,
                onBack = viewModel::clearSelectedThread,
                onRefresh = viewModel::refresh,
                enhancedVisuals = enhancedVisuals,
            )
        },
        bottomBar = {
            if (!wideLayout && !showConversationDetail) {
                BottomAppBar(
                    modifier = Modifier
                        .padding(
                            horizontal = if (enhancedVisuals) 16.dp else 0.dp,
                            vertical = if (enhancedVisuals) 10.dp else 0.dp,
                        )
                        .clip(if (enhancedVisuals) PanelShape else RoundedCornerShape(0.dp)),
                    tonalElevation = 0.dp,
                    containerColor = if (enhancedVisuals) {
                        MaterialTheme.colorScheme.surface.copy(alpha = 0.78f)
                    } else {
                        MaterialTheme.colorScheme.surface
                    },
                ) {
                    WorkspaceDestination.entries.forEach { item ->
                        NavigationBarItem(
                            selected = destination == item,
                            onClick = { onDestinationChange(item) },
                            icon = { Icon(item.icon, contentDescription = item.label) },
                            label = { Text(item.label) },
                        )
                    }
                }
            }
        },
        floatingActionButton = {
            if (destination == WorkspaceDestination.Chats && !showConversationDetail) {
                FilledTonalButton(
                    onClick = { onDestinationChange(WorkspaceDestination.Contacts) },
                    shape = RoundedCornerShape(18.dp),
                ) {
                    Icon(Icons.Rounded.PersonAdd, contentDescription = null)
                    Spacer(modifier = Modifier.width(10.dp))
                    Text("New chat")
                }
            }
        },
    ) { padding ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(screenBackgroundBrush(enhancedVisuals))
                .padding(padding),
        ) {
            Row(modifier = Modifier.fillMaxSize()) {
                if (wideLayout) {
                    NavigationRail(
                        containerColor = MaterialTheme.colorScheme.surface.copy(alpha = if (enhancedVisuals) 0.78f else 1f),
                        modifier = Modifier
                            .fillMaxHeight()
                            .padding(
                                start = if (enhancedVisuals) 12.dp else 0.dp,
                                top = if (enhancedVisuals) 12.dp else 0.dp,
                                bottom = if (enhancedVisuals) 12.dp else 0.dp,
                            )
                            .clip(if (enhancedVisuals) PanelShape else RoundedCornerShape(0.dp)),
                    ) {
                        Spacer(modifier = Modifier.height(12.dp))
                        WorkspaceDestination.entries.forEach { item ->
                            NavigationRailItem(
                                selected = destination == item,
                                onClick = { onDestinationChange(item) },
                                icon = { Icon(item.icon, contentDescription = item.label) },
                                label = { Text(item.label) },
                            )
                        }
                    }
                }

                Column(
                    modifier = Modifier
                        .weight(1f)
                        .fillMaxSize(),
                ) {
                    if (state.isBusy) {
                        AppLoadingIndicator(
                            enhanced = enhancedVisuals,
                            modifier = Modifier.fillMaxWidth(),
                        )
                    }

                    GlobalBanners(
                        errorMessage = state.errorMessage,
                        statusMessage = state.statusMessage,
                        transparencyWarnings = state.transparency.warnings,
                        transparencyResetAvailable = state.transparencyResetAvailable,
                        onResetTransparency = viewModel::resetTransparencyTrust,
                        showTransparencyWarning = destination != WorkspaceDestination.Security,
                        enhancedVisuals = enhancedVisuals,
                    )

                    AnimatedContent(
                        targetState = destination,
                        transitionSpec = {
                            val enterDuration = if (enhancedVisuals) 220 else 0
                            val exitDuration = if (enhancedVisuals) 160 else 0
                            (fadeIn(tween(enterDuration)) + slideInHorizontally(tween(enterDuration)) { width -> width / 18 }) togetherWith
                                (fadeOut(tween(exitDuration)) + slideOutHorizontally(tween(exitDuration)) { width -> -width / 18 })
                        },
                        label = "workspace-destination",
                    ) { currentDestination ->
                        when (currentDestination) {
                            WorkspaceDestination.Chats -> ChatsScreen(
                                state = state,
                                viewModel = viewModel,
                                activity = activity,
                                enhancedVisuals = enhancedVisuals,
                                chatQuery = chatQuery,
                                onChatQueryChange = onChatQueryChange,
                                onShowContacts = { onDestinationChange(WorkspaceDestination.Contacts) },
                                wideLayout = wideLayout,
                            )

                            WorkspaceDestination.Contacts -> ContactsScreen(
                                state = state,
                                viewModel = viewModel,
                                activity = activity,
                                enhancedVisuals = enhancedVisuals,
                                onOpenChat = { userId ->
                                    onDestinationChange(WorkspaceDestination.Chats)
                                    viewModel.openDirectChat(activity, userId)
                                },
                            )

                            WorkspaceDestination.Security -> SecurityScreen(
                                state = state,
                                viewModel = viewModel,
                                activity = activity,
                                enhancedVisuals = enhancedVisuals,
                            )

                            WorkspaceDestination.Settings -> SettingsScreen(
                                state = state,
                                viewModel = viewModel,
                                activity = activity,
                                enhancedVisuals = enhancedVisuals,
                                onExportArchive = onExportArchive,
                                onImportArchive = onImportArchive,
                                onOpenSecurity = { onDestinationChange(WorkspaceDestination.Security) },
                            )
                        }
                    }
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun WorkspaceTopBar(
    state: AppUiState,
    showConversationDetail: Boolean,
    selectedThread: ConversationThread?,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    enhancedVisuals: Boolean,
) {
    val title = if (showConversationDetail && selectedThread != null) {
        selectedThread.title.ifBlank { "Conversation" }
    } else {
        "Notrus"
    }
    val subtitle = if (showConversationDetail && selectedThread != null) {
        participantsSummary(selectedThread, state.currentIdentity?.id)
    } else {
        state.currentIdentity?.let { "@${it.username}" } ?: "Secure messaging"
    }
    val containerColor by animateColorAsState(
        targetValue = if (enhancedVisuals) {
            lerp(MaterialTheme.colorScheme.surface, MaterialTheme.colorScheme.primary, 0.025f).copy(alpha = 0.9f)
        } else {
            MaterialTheme.colorScheme.surface
        },
        animationSpec = tween(durationMillis = if (enhancedVisuals) 260 else 120),
        label = "topbar-container",
    )
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .statusBarsPadding()
            .padding(horizontal = 16.dp, vertical = 10.dp)
            .clip(PanelShape)
            .background(containerColor)
            .padding(horizontal = 14.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        if (showConversationDetail && selectedThread != null) {
            IconButton(onClick = onBack) {
                Icon(
                    Icons.AutoMirrored.Rounded.ArrowBack,
                    contentDescription = "Back",
                    tint = MaterialTheme.colorScheme.onSurface,
                )
            }
        }
        Column(
            modifier = Modifier.weight(1f),
            verticalArrangement = Arrangement.spacedBy(2.dp),
        ) {
            Text(
                text = title,
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onSurface,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                text = subtitle,
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
        if (state.currentIdentity != null) {
            IconButton(onClick = onRefresh) {
                Icon(
                    Icons.Rounded.Refresh,
                    contentDescription = "Refresh",
                    tint = MaterialTheme.colorScheme.onSurface,
                )
            }
        }
    }
}

@Composable
private fun GlobalBanners(
    errorMessage: String?,
    statusMessage: String,
    transparencyWarnings: List<String>,
    transparencyResetAvailable: Boolean,
    onResetTransparency: () -> Unit,
    showTransparencyWarning: Boolean,
    enhancedVisuals: Boolean,
) {
    val enterDuration = if (enhancedVisuals) 180 else 0
    val expandDuration = if (enhancedVisuals) 220 else 0
    val exitDuration = if (enhancedVisuals) 140 else 0
    val shrinkDuration = if (enhancedVisuals) 180 else 0
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        AnimatedVisibility(
            visible = errorMessage != null,
            enter = fadeIn(tween(enterDuration)) + expandVertically(tween(expandDuration, easing = FastOutSlowInEasing)),
            exit = fadeOut(tween(exitDuration)) + shrinkVertically(tween(shrinkDuration)),
        ) {
            errorMessage?.let {
                StatusBanner(message = it, tone = BannerTone.Warning)
            }
        }

        AnimatedVisibility(
            visible = showTransparencyWarning && transparencyWarnings.isNotEmpty(),
            enter = fadeIn(tween(enterDuration)) + expandVertically(tween(expandDuration, easing = FastOutSlowInEasing)),
            exit = fadeOut(tween(exitDuration)) + shrinkVertically(tween(shrinkDuration)),
        ) {
            if (showTransparencyWarning && transparencyWarnings.isNotEmpty()) {
                StatusBanner(
                    message = transparencyWarnings.first(),
                    tone = BannerTone.Warning,
                    actionLabel = if (transparencyResetAvailable) "Reset trust" else null,
                    onAction = if (transparencyResetAvailable) onResetTransparency else null,
                )
            }
        }

        AnimatedVisibility(
            visible = statusMessage != DefaultStatusMessage && errorMessage == null,
            enter = fadeIn(tween(enterDuration)) + expandVertically(tween(expandDuration, easing = FastOutSlowInEasing)),
            exit = fadeOut(tween(exitDuration)) + shrinkVertically(tween(shrinkDuration)),
        ) {
            if (statusMessage != DefaultStatusMessage && errorMessage == null) {
                StatusBanner(message = statusMessage, tone = BannerTone.Info)
            }
        }
    }
}

@Composable
private fun ChatsScreen(
    state: AppUiState,
    viewModel: NotrusViewModel,
    activity: FragmentActivity,
    enhancedVisuals: Boolean,
    chatQuery: String,
    onChatQueryChange: (String) -> Unit,
    onShowContacts: () -> Unit,
    wideLayout: Boolean,
) {
    val filteredThreads = remember(state.threads, chatQuery, state.currentIdentity?.id) {
        val query = chatQuery.trim().lowercase()
        if (query.isBlank()) {
            state.threads
        } else {
            state.threads.filter { thread ->
                thread.title.lowercase().contains(query) ||
                    participantsSummary(thread, state.currentIdentity?.id).lowercase().contains(query) ||
                    thread.messages.lastOrNull()?.body?.lowercase()?.contains(query) == true
            }
        }
    }
    val selectedThread = state.selectedThread

    if (wideLayout) {
        Row(
            modifier = Modifier.fillMaxSize(),
        ) {
            ChatListPane(
                state = state,
                enhancedVisuals = enhancedVisuals,
                threads = filteredThreads,
                chatQuery = chatQuery,
                onChatQueryChange = onChatQueryChange,
                onThreadClick = viewModel::selectThread,
                onShowContacts = onShowContacts,
                modifier = Modifier
                    .width(360.dp)
                    .fillMaxHeight(),
            )
            HorizontalDivider(
                modifier = Modifier
                    .fillMaxHeight()
                    .width(1.dp),
                color = MaterialTheme.colorScheme.outline.copy(alpha = 0.32f),
            )
            Box(
                modifier = Modifier
                    .weight(1f)
                    .fillMaxHeight(),
            ) {
                AnimatedContent(
                    targetState = selectedThread?.id,
                    transitionSpec = {
                        val enterDuration = if (enhancedVisuals) 220 else 0
                        val exitDuration = if (enhancedVisuals) 150 else 0
                        (fadeIn(tween(enterDuration)) + slideInHorizontally(tween(enterDuration)) { width -> width / 20 }) togetherWith
                            (fadeOut(tween(exitDuration)) + slideOutHorizontally(tween(exitDuration)) { width -> -width / 20 })
                    },
                    label = "wide-chat-selection",
                ) { selectedThreadId ->
                    val activeThread = state.threads.firstOrNull { it.id == selectedThreadId }
                    if (activeThread == null) {
                        EmptyState(
                            title = "Choose a conversation",
                            body = "Search contacts or pick an existing chat to start messaging from Android.",
                            actionLabel = "Open contacts",
                            onAction = onShowContacts,
                        )
                    } else {
                        ConversationPane(
                            state = state,
                            thread = activeThread,
                            activity = activity,
                            viewModel = viewModel,
                            enhancedVisuals = enhancedVisuals,
                            wideLayout = true,
                        )
                    }
                }
            }
        }
    } else {
        AnimatedContent(
            targetState = selectedThread?.id,
            transitionSpec = {
                val enterDuration = if (enhancedVisuals) 220 else 0
                val exitDuration = if (enhancedVisuals) 160 else 0
                (fadeIn(tween(enterDuration)) + slideInHorizontally(tween(enterDuration)) { width -> width / 12 }) togetherWith
                    (fadeOut(tween(exitDuration)) + slideOutHorizontally(tween(exitDuration)) { width -> -width / 14 })
            },
            label = "mobile-chat-navigation",
        ) { selectedThreadId ->
            val activeThread = state.threads.firstOrNull { it.id == selectedThreadId }
            if (activeThread != null) {
                ConversationPane(
                    state = state,
                    thread = activeThread,
                    activity = activity,
                    viewModel = viewModel,
                    enhancedVisuals = enhancedVisuals,
                    wideLayout = false,
                )
            } else {
                ChatListPane(
                    state = state,
                    enhancedVisuals = enhancedVisuals,
                    threads = filteredThreads,
                    chatQuery = chatQuery,
                    onChatQueryChange = onChatQueryChange,
                    onThreadClick = viewModel::selectThread,
                    onShowContacts = onShowContacts,
                    modifier = Modifier.fillMaxSize(),
                )
            }
        }
    }
}

@Composable
private fun ChatListPane(
    state: AppUiState,
    enhancedVisuals: Boolean,
    threads: List<ConversationThread>,
    chatQuery: String,
    onChatQueryChange: (String) -> Unit,
    onThreadClick: (String) -> Unit,
    onShowContacts: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val listState = rememberLazyListState()
    LazyColumn(
        modifier = modifier,
        state = listState,
        contentPadding = PaddingValues(horizontal = 16.dp, vertical = 16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        item {
            CurrentIdentityStrip(state = state, enhancedVisuals = enhancedVisuals)
        }

        item {
            OutlinedTextField(
                value = chatQuery,
                onValueChange = onChatQueryChange,
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                label = { Text("Search chats") },
                leadingIcon = {
                    Icon(Icons.Rounded.Search, contentDescription = null)
                },
            )
        }

        if (threads.isEmpty()) {
            item {
                EmptyStateCard(
                    title = if (chatQuery.isBlank()) "No conversations yet" else "No matching conversations",
                    body = if (chatQuery.isBlank()) {
                        "Start by searching for a contact and opening a direct chat."
                    } else {
                        "Try a different name or clear the chat search."
                    },
                    actionLabel = if (chatQuery.isBlank()) "Find contacts" else null,
                    onAction = if (chatQuery.isBlank()) onShowContacts else null,
                )
            }
        } else {
            items(threads, key = { it.id }) { thread ->
                ThreadListRow(
                    thread = thread,
                    enhancedVisuals = enhancedVisuals,
                    selected = thread.id == state.selectedThreadId,
                    currentUserId = state.currentIdentity?.id,
                    onClick = { onThreadClick(thread.id) },
                )
            }
        }
    }
}

@Composable
private fun ConversationPane(
    state: AppUiState,
    thread: ConversationThread,
    activity: FragmentActivity,
    viewModel: NotrusViewModel,
    enhancedVisuals: Boolean,
    wideLayout: Boolean,
) {
    val messageListState = rememberLazyListState()
    val canSend = thread.supported && state.draftText.isNotBlank() && !state.isBusy
    val sendScale by animateFloatAsState(
        targetValue = if (canSend) 1f else 0.94f,
        animationSpec = tween(durationMillis = 180, easing = FastOutSlowInEasing),
        label = "send-scale",
    )
    val sendContainerColor by animateColorAsState(
        targetValue = if (canSend) {
            MaterialTheme.colorScheme.primary
        } else {
            MaterialTheme.colorScheme.surfaceVariant
        },
        animationSpec = tween(durationMillis = 180),
        label = "send-container",
    )
    val sendContentColor by animateColorAsState(
        targetValue = if (canSend) {
            MaterialTheme.colorScheme.onPrimary
        } else {
            MaterialTheme.colorScheme.onSurfaceVariant
        },
        animationSpec = tween(durationMillis = 180),
        label = "send-content",
    )

    LaunchedEffect(thread.id, thread.messages.size) {
        if (thread.messages.isNotEmpty()) {
            messageListState.animateScrollToItem(thread.messages.lastIndex)
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background),
    ) {
        if (wideLayout) {
            ConversationHeader(thread = thread, currentUserId = state.currentIdentity?.id)
        }

        AnimatedVisibility(
            visible = thread.warning != null,
            enter = fadeIn(tween(180)) + expandVertically(tween(220, easing = FastOutSlowInEasing)),
            exit = fadeOut(tween(140)) + shrinkVertically(tween(180)),
        ) {
            thread.warning?.let {
                StatusBanner(
                    message = it,
                    tone = BannerTone.Warning,
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
                )
            }
        }

        if (thread.messages.isEmpty()) {
            Box(modifier = Modifier.weight(1f)) {
                EmptyState(
                    title = "No messages yet",
                    body = "This conversation is ready. Send the first encrypted message from Android.",
                )
            }
        } else {
            LazyColumn(
                modifier = Modifier.weight(1f),
                state = messageListState,
                contentPadding = PaddingValues(horizontal = 16.dp, vertical = 16.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                items(thread.messages, key = { it.id }) { message ->
                    MessageBubble(
                        message = message,
                        enhancedVisuals = enhancedVisuals,
                        isLocal = message.senderId == state.currentIdentity?.id,
                    )
                }
            }
        }

        HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.2f))
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 12.dp)
                .navigationBarsPadding(),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(if (enhancedVisuals) PanelShape else RoundedCornerShape(0.dp))
                    .background(
                        if (enhancedVisuals) {
                            MaterialTheme.colorScheme.surface.copy(alpha = 0.8f)
                        } else {
                            Color.Transparent
                        },
                    )
                    .padding(
                        horizontal = if (enhancedVisuals) 14.dp else 0.dp,
                        vertical = if (enhancedVisuals) 12.dp else 0.dp,
                    ),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        text = if (thread.supported) "Secure direct chat" else "Read-only thread on Android",
                        style = MaterialTheme.typography.labelLarge,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    TextButton(onClick = { viewModel.deleteConversation(thread.id) }) {
                        Text("Delete local")
                    }
                }
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.Bottom,
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    OutlinedTextField(
                        value = state.draftText,
                        onValueChange = viewModel::updateDraftText,
                        modifier = Modifier.weight(1f),
                        label = { Text("Message") },
                        minLines = 1,
                        maxLines = 4,
                        enabled = thread.supported,
                    )
                    FilledIconButton(
                        onClick = { viewModel.sendSelectedMessage(activity) },
                        enabled = canSend,
                        modifier = Modifier.graphicsLayer {
                            scaleX = sendScale
                            scaleY = sendScale
                        },
                        colors = IconButtonDefaults.filledIconButtonColors(
                            containerColor = sendContainerColor,
                            contentColor = sendContentColor,
                        ),
                    ) {
                        Icon(Icons.AutoMirrored.Rounded.Send, contentDescription = "Send")
                    }
                }
            }
        }
    }
}

@Composable
private fun ConversationHeader(
    thread: ConversationThread,
    currentUserId: String?,
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 16.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        Text(
            text = thread.title.ifBlank { "Conversation" },
            style = MaterialTheme.typography.headlineSmall,
            color = MaterialTheme.colorScheme.onBackground,
            maxLines = 2,
            overflow = TextOverflow.Ellipsis,
        )
        Text(
            text = participantsSummary(thread, currentUserId),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            InlineStatusBadge(
                label = thread.protocolLabel,
                tone = MaterialTheme.colorScheme.primary,
            )
            InlineStatusBadge(
                label = if (thread.supported) "Ready to send" else "Read only",
                tone = if (thread.supported) successTone() else MaterialTheme.colorScheme.tertiary,
            )
        }
    }
}

@Composable
private fun ContactsScreen(
    state: AppUiState,
    viewModel: NotrusViewModel,
    activity: FragmentActivity,
    enhancedVisuals: Boolean,
    onOpenChat: (String) -> Unit,
) {
    val query = state.directoryQuery.trim()
    val savedMatches = remember(state.contacts, query) {
        if (query.isBlank()) {
            state.contacts
        } else {
            state.contacts.filter { user ->
                user.displayName.contains(query, ignoreCase = true) ||
                    user.username.contains(query, ignoreCase = true) ||
                    (user.directoryCode?.contains(query, ignoreCase = true) == true)
            }
        }
    }
    val relayMatches = remember(state.directoryResults, query, state.currentIdentity?.id) {
        state.directoryResults.filter { user ->
            user.id != state.currentIdentity?.id &&
                (query.isBlank() ||
                    user.displayName.contains(query, ignoreCase = true) ||
                    user.username.contains(query, ignoreCase = true) ||
                    (user.directoryCode?.contains(query, ignoreCase = true) == true))
        }
    }
    val combinedMatches = remember(savedMatches, relayMatches) {
        (savedMatches + relayMatches).distinctBy { it.id }
    }

    LaunchedEffect(query, state.currentIdentity?.id) {
        if (query.length >= MinimumDirectorySearchLength) {
            delay(280)
            if (query == state.directoryQuery.trim()) {
                viewModel.searchDirectory()
            }
        }
    }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(horizontal = 16.dp, vertical = 16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        item {
            CurrentIdentityStrip(state = state, enhancedVisuals = enhancedVisuals)
        }

        item {
            SectionCard(
                title = "Find people",
                subtitle = "Search by username or invite code. Local saved contacts appear immediately, and relay matches are merged in after lookup.",
                enhanced = enhancedVisuals,
                accent = MaterialTheme.colorScheme.secondary,
            ) {
                OutlinedTextField(
                    value = state.directoryQuery,
                    onValueChange = viewModel::updateDirectoryQuery,
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    label = { Text("Search username or invite code") },
                    leadingIcon = {
                        Icon(Icons.Rounded.Search, contentDescription = null)
                    },
                )
                Text(
                    text = if (query.length >= MinimumDirectorySearchLength) {
                        "Searching local contacts first, then the relay."
                    } else {
                        "Enter at least $MinimumDirectorySearchLength characters for relay search."
                    },
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }

        if (query.isBlank()) {
            item {
                SectionHeader(
                    title = "Saved contacts",
                    subtitle = if (state.contacts.isEmpty()) "No local contacts saved yet." else null,
                )
            }
            if (state.contacts.isEmpty()) {
                item {
                    EmptyStateCard(
                        title = "No saved contacts",
                        body = "Search by username or invite code to save a contact into the local vault.",
                    )
                }
            } else {
                items(state.contacts, key = { it.id }) { user ->
                    ContactListRow(
                        user = user,
                        enhancedVisuals = enhancedVisuals,
                        saved = true,
                        onSave = null,
                        onDelete = { viewModel.deleteContact(user.id) },
                        onMessage = { onOpenChat(user.id) },
                    )
                }
            }
        } else {
            item {
                SectionHeader(
                    title = "Results",
                    subtitle = if (combinedMatches.isEmpty() && query.length >= MinimumDirectorySearchLength && !state.isBusy) {
                        "No local or relay matches found."
                    } else null,
                )
            }

            if (combinedMatches.isEmpty() && query.length < MinimumDirectorySearchLength) {
                item {
                    EmptyStateCard(
                        title = "Keep typing",
                        body = "Short searches show only immediate local matches. The relay search starts at three characters.",
                    )
                }
            } else if (combinedMatches.isEmpty() && !state.isBusy) {
                item {
                    EmptyStateCard(
                        title = "No matches",
                        body = "Try the exact username or the other person's invite code.",
                    )
                }
            } else {
                items(combinedMatches, key = { it.id }) { user ->
                    val saved = state.contacts.any { it.id == user.id }
                    ContactListRow(
                        user = user,
                        enhancedVisuals = enhancedVisuals,
                        saved = saved,
                        onSave = if (saved) null else { { viewModel.saveContact(user.id) } },
                        onDelete = if (saved) { { viewModel.deleteContact(user.id) } } else null,
                        onMessage = { onOpenChat(user.id) },
                    )
                }
            }
        }
    }
}

@Composable
private fun SecurityScreen(
    state: AppUiState,
    viewModel: NotrusViewModel,
    activity: FragmentActivity,
    enhancedVisuals: Boolean,
) {
    var transparencyDetailsExpanded by rememberSaveable { mutableStateOf(false) }
    var deviceDetailsExpanded by rememberSaveable { mutableStateOf(false) }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(horizontal = 16.dp, vertical = 16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        item {
            TrustOverviewCard(state = state, enhancedVisuals = enhancedVisuals)
        }

        item {
            SectionCard(
                title = "Transparency and relay trust",
                subtitle = "Security warnings stay visible here without overwhelming the normal chat flow.",
                enhanced = enhancedVisuals,
                accent = MaterialTheme.colorScheme.tertiary,
            ) {
                StatusRow(
                    title = "Transparency log",
                    value = if (state.transparency.chainValid) "Verified" else "Needs review",
                    tone = if (state.transparency.chainValid) successTone() else MaterialTheme.colorScheme.tertiary,
                )
                FilterChip(
                    selected = transparencyDetailsExpanded,
                    onClick = { transparencyDetailsExpanded = !transparencyDetailsExpanded },
                    label = { Text(if (transparencyDetailsExpanded) "Hide relay details" else "Show relay details") },
                )
                AnimatedVisibility(
                    visible = transparencyDetailsExpanded,
                    enter = fadeIn(tween(180)) + expandVertically(tween(220, easing = FastOutSlowInEasing)),
                    exit = fadeOut(tween(140)) + shrinkVertically(tween(180)),
                ) {
                    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                        state.transparency.head?.let { head ->
                            DetailLine(label = "Current head", value = head.take(18))
                        }
                        state.relayHealth?.let { health ->
                            DetailLine(label = "Relay protocol", value = health.protocolLabel)
                            DetailLine(label = "Transport", value = health.transportLabel.uppercase())
                            health.directoryDiscoveryMode?.let { mode ->
                                DetailLine(label = "Discovery", value = mode.replace('-', ' '))
                            }
                        }
                    }
                }
                if (state.transparency.warnings.isNotEmpty()) {
                    StatusBanner(
                        message = state.transparency.warnings.first(),
                        tone = BannerTone.Warning,
                    )
                }
                if (state.transparencyResetAvailable) {
                    FilledTonalButton(
                        onClick = viewModel::resetTransparencyTrust,
                        enabled = !state.isBusy,
                        shape = RoundedCornerShape(16.dp),
                    ) {
                        Text("Reset transparency trust")
                    }
                }
            }
        }

        item {
            SectionCard(
                title = "This device",
                subtitle = "Current device state and integrity summary.",
                enhanced = enhancedVisuals,
            ) {
                state.currentDevice?.let { device ->
                    DetailLine(label = "Device", value = device.label)
                    DetailLine(label = "Risk", value = device.riskLevel.uppercase())
                }
                FilterChip(
                    selected = deviceDetailsExpanded,
                    onClick = { deviceDetailsExpanded = !deviceDetailsExpanded },
                    label = { Text(if (deviceDetailsExpanded) "Hide integrity details" else "Show integrity details") },
                )
                AnimatedVisibility(
                    visible = deviceDetailsExpanded,
                    enter = fadeIn(tween(180)) + expandVertically(tween(220, easing = FastOutSlowInEasing)),
                    exit = fadeOut(tween(140)) + shrinkVertically(tween(180)),
                ) {
                    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                        state.currentDevice?.let { device ->
                            DetailLine(label = "Device ID", value = device.id)
                            DetailLine(label = "Storage", value = device.storageMode ?: "Unknown")
                        }
                        state.integrityReport?.let { report ->
                            HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.2f))
                            DetailLine(label = "Code signature", value = report.codeSignatureStatus)
                            DetailLine(label = "Device check", value = report.deviceCheckStatus)
                            DetailLine(label = "Risk level", value = report.riskLevel.uppercase())
                        }
                    }
                }
            }
        }

        item {
            SectionHeader(
                title = "Linked devices",
                subtitle = if (state.linkedDevices.isEmpty()) "No linked devices registered yet." else null,
            )
        }

        if (state.linkedDevices.isEmpty()) {
            item {
                EmptyStateCard(
                    title = "No linked devices",
                    body = "When more devices are linked, you can review and revoke them here.",
                )
            }
        } else {
            items(state.linkedDevices, key = { it.id }) { device ->
                LinkedDeviceRow(
                    device = device,
                    enhancedVisuals = enhancedVisuals,
                    onRevoke = if (!device.current && device.revokedAt == null) {
                        { viewModel.revokeLinkedDevice(activity, device.id) }
                    } else {
                        null
                    },
                )
            }
        }

        item {
            SectionCard(
                title = "Protocol core",
                subtitle = state.protocolEngineMessage,
                enhanced = enhancedVisuals,
                accent = MaterialTheme.colorScheme.primary,
            ) {
                Text(
                    text = "Keep advanced protocol state visible here rather than mixing it into every conversation screen.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

@Composable
private fun SettingsScreen(
    state: AppUiState,
    viewModel: NotrusViewModel,
    activity: FragmentActivity,
    enhancedVisuals: Boolean,
    onExportArchive: () -> Unit,
    onImportArchive: () -> Unit,
    onOpenSecurity: () -> Unit,
) {
    val scrollState = rememberScrollState()
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(scrollState)
            .padding(horizontal = 16.dp, vertical = 16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        SectionCard(
            title = "General",
            subtitle = "Manage local identities and account basics stored in the encrypted Android vault.",
            enhanced = enhancedVisuals,
        ) {
            if (state.profiles.isEmpty()) {
                Text(
                    text = "No profiles stored locally.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            } else {
                state.profiles.forEach { profile ->
                    ProfileRow(
                        profile = profile,
                        enhancedVisuals = enhancedVisuals,
                        current = state.currentIdentity?.id == profile.id,
                        onSwitch = if (state.currentIdentity?.id != profile.id) {
                            { viewModel.switchProfile(profile.id) }
                        } else {
                            null
                        },
                        onDelete = { viewModel.deleteProfile(activity, profile.id) },
                    )
                }
            }

            HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.2f))

            Text(
                text = "Create another profile",
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onSurface,
            )
            OutlinedTextField(
                value = state.onboardingDisplayName,
                onValueChange = viewModel::updateOnboardingDisplayName,
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                label = { Text("Display name") },
            )
            OutlinedTextField(
                value = state.onboardingUsername,
                onValueChange = viewModel::updateOnboardingUsername,
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                label = { Text("Username") },
            )
            Button(
                onClick = viewModel::createProfile,
                enabled = !state.isBusy,
                shape = RoundedCornerShape(16.dp),
            ) {
                Icon(Icons.Rounded.PersonAdd, contentDescription = null)
                Spacer(modifier = Modifier.width(10.dp))
                Text("Create profile")
            }
        }

        SectionCard(
            title = "Security",
            subtitle = "Fast access to trust verification, linked-device controls, and integrity state.",
            enhanced = enhancedVisuals,
            accent = MaterialTheme.colorScheme.tertiary,
        ) {
            Text(
                text = "Open security workspace",
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onSurface,
            )
            Text(
                text = "Review transparency trust, linked devices, and device-integrity details in one place.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            FilledTonalButton(
                onClick = onOpenSecurity,
                shape = RoundedCornerShape(16.dp),
            ) {
                Icon(Icons.Rounded.Security, contentDescription = null)
                Spacer(modifier = Modifier.width(10.dp))
                Text("Open security")
            }
        }

        SectionCard(
            title = "Devices",
            subtitle = "Current device and linked-device overview.",
            enhanced = enhancedVisuals,
            accent = MaterialTheme.colorScheme.secondary,
        ) {
            DetailLine(
                label = "Current device",
                value = state.currentDevice?.label ?: "Unknown",
            )
            DetailLine(
                label = "Storage mode",
                value = state.currentDevice?.storageMode ?: "Unknown",
            )
            DetailLine(
                label = "Linked devices",
                value = state.linkedDevices.size.toString(),
            )
        }

        SectionCard(
            title = "Privacy",
            subtitle = "Safe defaults stay on by default. Privacy mode adds small randomized delays to weaken simple timing correlation.",
            enhanced = enhancedVisuals,
            accent = MaterialTheme.colorScheme.secondary,
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(
                    modifier = Modifier.weight(1f),
                    verticalArrangement = Arrangement.spacedBy(4.dp),
                ) {
                    Text(
                        text = "Privacy mode",
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                    Text(
                        text = if (state.privacyModeEnabled) {
                            "On. Routine sync, search, and send operations use a short randomized delay."
                        } else {
                            "Off. The app uses the fastest routine relay path."
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Switch(
                    checked = state.privacyModeEnabled,
                    onCheckedChange = viewModel::updatePrivacyMode,
                )
            }
        }

        SectionCard(
            title = "Appearance",
            subtitle = "Choose light, dark, or system mode plus the global color theme and visual intensity.",
            enhanced = enhancedVisuals,
            accent = MaterialTheme.colorScheme.primary,
        ) {
            Text(
                text = "Mode",
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onSurface,
            )
            FlowRow(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                NotrusThemeMode.entries.forEach { mode ->
                    FilterChip(
                        selected = state.themeMode == mode.key,
                        onClick = { viewModel.updateThemeMode(mode.key) },
                        label = { Text(mode.label) },
                    )
                }
            }
            Text(
                text = when (NotrusThemeMode.fromKey(state.themeMode)) {
                    NotrusThemeMode.System -> "Follows Android system light or dark mode."
                    NotrusThemeMode.Light -> "Forces the light appearance until you change it."
                    NotrusThemeMode.Dark -> "Forces the dark appearance until you change it."
                },
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.2f))

            Text(
                text = "Color theme",
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onSurface,
            )
            FlowRow(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                NotrusColorTheme.entries.forEach { theme ->
                    FilterChip(
                        selected = state.colorThemePreset == theme.key,
                        onClick = { viewModel.updateColorTheme(theme.key) },
                        label = { Text(theme.label) },
                    )
                }
            }
            Text(
                text = "Theme applies across chats, contacts, account, and security screens.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.2f))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(
                    modifier = Modifier.weight(1f),
                    verticalArrangement = Arrangement.spacedBy(4.dp),
                ) {
                    Text(
                        text = "Enhanced visuals",
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                    Text(
                        text = if (state.visualEffectsEnabled) {
                            "On. Animated glow layers and richer surfaces are active."
                        } else {
                            "Off. Android uses the lightest rendering path for older or weaker devices."
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Switch(
                    checked = state.visualEffectsEnabled,
                    onCheckedChange = viewModel::updateVisualEffects,
                )
            }
        }

        SectionCard(
            title = "Relay",
            subtitle = "Use the same relay on all devices. Remote use should go through HTTPS.",
            enhanced = enhancedVisuals,
        ) {
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
                label = { Text("Witness origins") },
            )
            state.relayHealth?.let { health ->
                DetailLine(label = "Users", value = health.users.toString())
                DetailLine(label = "Threads", value = health.threads.toString())
                DetailLine(label = "Transport", value = health.transportLabel.uppercase())
            }
        }

        SectionCard(
            title = "Recovery",
            subtitle = "Export and import encrypted recovery archives. Cross-platform recovery is not fully stable yet.",
            enhanced = enhancedVisuals,
            accent = MaterialTheme.colorScheme.tertiary,
        ) {
            OutlinedTextField(
                value = state.exportPassphrase,
                onValueChange = viewModel::updateExportPassphrase,
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                label = { Text("Export passphrase") },
            )
            FilledTonalButton(
                onClick = onExportArchive,
                enabled = !state.isBusy && state.currentIdentity != null,
                shape = RoundedCornerShape(16.dp),
            ) {
                Icon(Icons.Rounded.Download, contentDescription = null)
                Spacer(modifier = Modifier.width(10.dp))
                Text("Export current profile")
            }

            HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.2f))

            OutlinedTextField(
                value = state.importPassphrase,
                onValueChange = viewModel::updateImportPassphrase,
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                label = { Text("Import passphrase") },
            )
            FilledTonalButton(
                onClick = onImportArchive,
                enabled = !state.isBusy,
                shape = RoundedCornerShape(16.dp),
            ) {
                Icon(Icons.Rounded.Upload, contentDescription = null)
                Spacer(modifier = Modifier.width(10.dp))
                Text("Import recovery archive")
            }
            StatusBanner(
                message = "Known issue: Android to macOS recovery import is still not reliable enough to treat as a stable migration path.",
                tone = BannerTone.Warning,
            )
        }

        SectionCard(
            title = "Advanced",
            subtitle = "Local vault and Keystore inventory for device-level troubleshooting and testing.",
            enhanced = enhancedVisuals,
        ) {
            DetailLine(
                label = "Vault catalog",
                value = if (state.deviceInventory.vaultCatalogPresent) "Present" else "Missing",
            )
            DetailLine(
                label = "Vault key",
                value = if (state.deviceInventory.vaultMasterAliasPresent) "Ready" else "Missing",
            )
            state.deviceInventory.appInstanceId?.let { DetailLine(label = "App instance", value = it) }
            state.deviceInventory.deviceKeyAlias?.let { alias ->
                DetailLine(label = "Device key alias", value = alias)
            }

            if (state.deviceInventory.profiles.isNotEmpty()) {
                HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.2f))
                Text(
                    text = "Stored profiles",
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onSurface,
                )
                state.deviceInventory.profiles.forEach { profile ->
                    DeviceInventoryProfileRow(profile = profile)
                }
            }

            if (state.deviceInventory.hardwareAliases.isNotEmpty()) {
                HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.2f))
                Text(
                    text = "Keystore aliases",
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onSurface,
                )
                state.deviceInventory.hardwareAliases.forEach { alias ->
                    DeviceInventoryAliasRow(alias = alias)
                }
            }
        }
    }
}

@Composable
private fun CurrentIdentityStrip(state: AppUiState, enhancedVisuals: Boolean) {
    val identity = state.currentIdentity
    SectionCard(
        title = identity?.displayName ?: "Current profile",
        subtitle = identity?.let { "@${it.username}" } ?: "No active profile",
        enhanced = enhancedVisuals,
        accent = MaterialTheme.colorScheme.primary,
    ) {
        DetailLine(
            label = "Invite code",
            value = state.currentDirectoryCode ?: "Pending relay registration",
        )
        state.currentDevice?.let { device ->
            DetailLine(label = "This device", value = device.label)
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            if (state.transparency.chainValid) {
                InlineStatusBadge(
                    label = "Relay trust verified",
                    tone = successTone(),
                )
            } else {
                InlineStatusBadge(
                    label = "Trust review",
                    tone = MaterialTheme.colorScheme.tertiary,
                )
            }
            state.relayHealth?.let { health ->
                InlineStatusBadge(
                    label = health.protocolLabel,
                    tone = MaterialTheme.colorScheme.primary,
                )
            }
        }
    }
}

@Composable
private fun TrustOverviewCard(state: AppUiState, enhancedVisuals: Boolean) {
    SectionCard(
        title = "Security overview",
        subtitle = "Important trust signals are visible here without turning the app into a diagnostics panel.",
        enhanced = enhancedVisuals,
        accent = MaterialTheme.colorScheme.secondary,
    ) {
        StatusRow(
            title = "Transparency",
            value = if (state.transparency.chainValid) "Verified" else "Needs review",
            tone = if (state.transparency.chainValid) successTone() else MaterialTheme.colorScheme.tertiary,
        )
        StatusRow(
            title = "Current device",
            value = state.currentDevice?.storageMode ?: "Unknown",
            tone = MaterialTheme.colorScheme.primary,
        )
        StatusRow(
            title = "Privacy mode",
            value = if (state.privacyModeEnabled) "Enabled" else "Disabled",
            tone = if (state.privacyModeEnabled) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun SectionCard(
    title: String,
    subtitle: String? = null,
    enhanced: Boolean = false,
    accent: Color = MaterialTheme.colorScheme.primary,
    content: @Composable ColumnScope.() -> Unit,
) {
    val containerColor by animateColorAsState(
        targetValue = if (enhanced) {
            lerp(MaterialTheme.colorScheme.surface, accent, 0.025f).copy(alpha = 0.88f)
        } else {
            MaterialTheme.colorScheme.surface
        },
        animationSpec = tween(durationMillis = if (enhanced) 260 else 120),
        label = "section-card-container",
    )
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(PanelShape)
            .background(containerColor)
            .animateContentSize(
                animationSpec = tween(durationMillis = 220, easing = FastOutSlowInEasing),
            )
            .padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
        content = {
            Text(
                text = title,
                style = MaterialTheme.typography.titleLarge,
                color = MaterialTheme.colorScheme.onSurface,
            )
            subtitle?.let {
                Text(
                    text = it,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            content()
        },
    )
}

@Composable
private fun SectionHeader(
    title: String,
    subtitle: String? = null,
) {
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(
            text = title,
            style = MaterialTheme.typography.titleLarge,
            color = MaterialTheme.colorScheme.onBackground,
        )
        subtitle?.let {
            Text(
                text = it,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun AppLoadingIndicator(
    enhanced: Boolean,
    modifier: Modifier = Modifier,
) {
    if (!enhanced) {
        LinearProgressIndicator(modifier = modifier)
        return
    }

    Column(
        modifier = modifier.padding(horizontal = 12.dp, vertical = 8.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(14.dp))
                .background(MaterialTheme.colorScheme.surface.copy(alpha = 0.62f)),
        ) {
            LinearProgressIndicator(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(6.dp),
                color = MaterialTheme.colorScheme.primary.copy(alpha = 0.9f),
                trackColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.42f),
                strokeCap = StrokeCap.Round,
            )
        }
    }
}

@Composable
private fun StatusBanner(
    message: String,
    tone: BannerTone,
    modifier: Modifier = Modifier,
    actionLabel: String? = null,
    onAction: (() -> Unit)? = null,
) {
    val containerColor: Color
    val contentColor: Color
    val icon = when (tone) {
        BannerTone.Info -> Icons.Rounded.Info
        BannerTone.Warning -> Icons.Rounded.WarningAmber
        BannerTone.Success -> Icons.Rounded.CheckCircle
    }
    when (tone) {
        BannerTone.Info -> {
            containerColor = MaterialTheme.colorScheme.primaryContainer
            contentColor = MaterialTheme.colorScheme.onPrimaryContainer
        }

        BannerTone.Warning -> {
            containerColor = MaterialTheme.colorScheme.errorContainer
            contentColor = MaterialTheme.colorScheme.onErrorContainer
        }

        BannerTone.Success -> {
            containerColor = successTone().copy(alpha = 0.14f)
            contentColor = MaterialTheme.colorScheme.onSurface
        }
    }

    Column(
        modifier = modifier
            .fillMaxWidth()
            .clip(RowShape)
            .background(containerColor.copy(alpha = 0.82f))
            .padding(horizontal = 14.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            verticalAlignment = Alignment.Top,
        ) {
            Icon(
                imageVector = icon,
                contentDescription = null,
                tint = contentColor,
            )
            Text(
                text = message,
                modifier = Modifier.weight(1f),
                style = MaterialTheme.typography.bodyMedium,
                color = contentColor,
            )
        }
        if (actionLabel != null && onAction != null) {
            TextButton(onClick = onAction) {
                Text(actionLabel)
            }
        }
    }
}

@Composable
private fun ThreadListRow(
    thread: ConversationThread,
    enhancedVisuals: Boolean,
    selected: Boolean,
    currentUserId: String?,
    onClick: () -> Unit,
) {
    val preview = thread.messages.lastOrNull()?.body?.takeIf { it.isNotBlank() }
        ?: participantsSummary(thread, currentUserId)

    val rowColor by animateColorAsState(
        targetValue = if (selected) {
            MaterialTheme.colorScheme.primaryContainer.copy(alpha = if (enhancedVisuals) 0.88f else 1f)
        } else {
            MaterialTheme.colorScheme.surface.copy(alpha = if (enhancedVisuals) 0.9f else 1f)
        },
        animationSpec = tween(durationMillis = 180),
        label = "thread-row-color",
    )
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RowShape)
            .background(rowColor)
            .clickable(onClick = onClick)
            .animateContentSize(animationSpec = tween(durationMillis = 180, easing = FastOutSlowInEasing))
            .padding(horizontal = 16.dp, vertical = 14.dp),
        horizontalArrangement = Arrangement.spacedBy(14.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
            Surface(
                shape = CircleShape,
                color = if (selected) {
                    MaterialTheme.colorScheme.primary
                } else {
                    MaterialTheme.colorScheme.secondaryContainer
                },
            ) {
                Text(
                    text = (thread.title.ifBlank { participantsSummary(thread, currentUserId) }).take(1).uppercase(),
                    modifier = Modifier.padding(horizontal = 14.dp, vertical = 10.dp),
                    style = MaterialTheme.typography.titleMedium,
                    color = if (selected) MaterialTheme.colorScheme.onPrimary else MaterialTheme.colorScheme.onSecondaryContainer,
                )
            }

            Column(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                Text(
                    text = thread.title.ifBlank { participantsSummary(thread, currentUserId) },
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onSurface,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    text = preview,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )
                thread.warning?.let {
                    Text(
                        text = it,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.tertiary,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
            }

            Column(horizontalAlignment = Alignment.End) {
                Text(
                    text = formatConversationTimestamp(thread.lastActivityAt),
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Text(
                    text = "${thread.messageCount}",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
    }
}

@Composable
private fun ContactListRow(
    user: RelayUser,
    enhancedVisuals: Boolean,
    saved: Boolean,
    onSave: (() -> Unit)?,
    onDelete: (() -> Unit)?,
    onMessage: () -> Unit,
) {
    val rowColor by animateColorAsState(
        targetValue = if (enhancedVisuals) {
            lerp(MaterialTheme.colorScheme.surface, MaterialTheme.colorScheme.secondary, 0.02f).copy(alpha = 0.9f)
        } else {
            MaterialTheme.colorScheme.surface
        },
        animationSpec = tween(durationMillis = 180),
        label = "contact-row-color",
    )
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RowShape)
            .background(rowColor)
            .animateContentSize(animationSpec = tween(durationMillis = 180, easing = FastOutSlowInEasing))
            .padding(horizontal = 16.dp, vertical = 14.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(14.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Surface(
                    shape = CircleShape,
                    color = MaterialTheme.colorScheme.secondaryContainer,
                ) {
                    Text(
                        text = user.displayName.ifBlank { user.username }.take(1).uppercase(),
                        modifier = Modifier.padding(horizontal = 14.dp, vertical = 10.dp),
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.onSecondaryContainer,
                    )
                }
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = user.displayName.ifBlank { user.username },
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                    Text(
                        text = "@${user.username}",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                if (saved) {
                    InlineStatusBadge(
                        label = "Saved",
                        tone = successTone(),
                    )
                }
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                FilledTonalButton(
                    onClick = onMessage,
                    enabled = user.signalBundle != null,
                    shape = RoundedCornerShape(16.dp),
                ) {
                    Text(if (user.signalBundle != null) "Message" else "Direct unavailable")
                }
                onSave?.let {
                    TextButton(onClick = it) {
                        Text("Save")
                    }
                }
                onDelete?.let {
                    TextButton(onClick = it) {
                        Text("Delete")
                    }
                }
            }
    }
}

@Composable
private fun LinkedDeviceRow(
    device: RelayLinkedDevice,
    enhancedVisuals: Boolean,
    onRevoke: (() -> Unit)?,
) {
    val rowColor by animateColorAsState(
        targetValue = if (enhancedVisuals) {
            lerp(MaterialTheme.colorScheme.surface, MaterialTheme.colorScheme.tertiary, 0.02f).copy(alpha = 0.9f)
        } else {
            MaterialTheme.colorScheme.surface
        },
        animationSpec = tween(durationMillis = 180),
        label = "linked-device-row-color",
    )
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RowShape)
            .background(rowColor)
            .animateContentSize(animationSpec = tween(durationMillis = 180, easing = FastOutSlowInEasing))
            .padding(horizontal = 16.dp, vertical = 14.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
            Text(
                text = device.label,
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onSurface,
            )
            Text(
                text = "${device.platform} · ${device.id}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                if (device.current) {
                    InlineStatusBadge(label = "This device", tone = MaterialTheme.colorScheme.primary)
                }
                if (device.revokedAt != null) {
                    InlineStatusBadge(label = "Revoked", tone = MaterialTheme.colorScheme.tertiary)
                } else {
                    InlineStatusBadge(label = "Risk ${device.riskLevel.uppercase()}", tone = successTone())
                }
                device.attestationStatus?.let {
                    InlineStatusBadge(label = it.replace('-', ' '), tone = MaterialTheme.colorScheme.primary)
                }
            }
            device.attestationNote?.let {
                Text(
                    text = it,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            onRevoke?.let {
                TextButton(onClick = it) {
                    Text("Revoke linked device")
                }
            }
    }
}

@Composable
private fun ProfileRow(
    profile: com.notrus.android.model.LocalIdentity,
    enhancedVisuals: Boolean,
    current: Boolean,
    onSwitch: (() -> Unit)?,
    onDelete: () -> Unit,
) {
    val rowColor by animateColorAsState(
        targetValue = if (enhancedVisuals) {
            lerp(MaterialTheme.colorScheme.surface, MaterialTheme.colorScheme.primary, 0.02f).copy(alpha = 0.9f)
        } else {
            MaterialTheme.colorScheme.surface
        },
        animationSpec = tween(durationMillis = 180),
        label = "profile-row-color",
    )
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RowShape)
            .background(rowColor)
            .animateContentSize(animationSpec = tween(durationMillis = 180, easing = FastOutSlowInEasing))
            .padding(horizontal = 14.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = profile.displayName,
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                    Text(
                        text = "@${profile.username}",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                if (current) {
                    InlineStatusBadge(label = "Active", tone = successTone())
                }
            }
            FlowRow(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                InlineStatusBadge(label = profile.storageMode, tone = MaterialTheme.colorScheme.primary)
                profile.directoryCode?.let {
                    InlineStatusBadge(label = "Invite $it", tone = successTone())
                }
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                onSwitch?.let {
                    FilledTonalButton(onClick = it, shape = RoundedCornerShape(14.dp)) {
                        Text("Switch")
                    }
                }
                TextButton(onClick = onDelete) {
                    Text("Delete local profile")
                }
            }
    }
}

@Composable
private fun DeviceInventoryProfileRow(profile: DeviceInventoryProfile) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RowShape)
            .background(MaterialTheme.colorScheme.surface.copy(alpha = 0.82f))
            .padding(horizontal = 14.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
            Text(
                text = profile.displayName,
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onSurface,
            )
            Text(
                text = "@${profile.username}",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            FlowRow(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                InlineStatusBadge(label = profile.storageMode, tone = MaterialTheme.colorScheme.primary)
                if (profile.missingAliasKinds.isEmpty()) {
                    InlineStatusBadge(label = "Aliases present", tone = successTone())
                } else {
                    InlineStatusBadge(
                        label = "Missing ${profile.missingAliasKinds.joinToString("/")}",
                        tone = MaterialTheme.colorScheme.tertiary,
                    )
                }
            }
    }
}

@Composable
private fun DeviceInventoryAliasRow(alias: DeviceInventoryAlias) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RowShape)
            .background(MaterialTheme.colorScheme.surface.copy(alpha = 0.82f))
            .padding(horizontal = 14.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
            Text(
                text = alias.alias,
                style = MaterialTheme.typography.labelLarge,
                color = MaterialTheme.colorScheme.onSurface,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                text = listOfNotNull(
                    alias.kind,
                    alias.storageMode,
                    alias.ownerId?.let { "owner $it" },
                    alias.linkedProfileId?.let { "linked" } ?: "stale",
                ).joinToString(" · "),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
    }
}

@Composable
private fun MessageBubble(
    message: DecryptedMessage,
    enhancedVisuals: Boolean,
    isLocal: Boolean,
) {
    val bubbleColor by animateColorAsState(
        targetValue = when {
            message.status != "ok" -> MaterialTheme.colorScheme.errorContainer.copy(alpha = if (enhancedVisuals) 0.84f else 1f)
            isLocal -> MaterialTheme.colorScheme.primaryContainer.copy(alpha = if (enhancedVisuals) 0.88f else 1f)
            else -> MaterialTheme.colorScheme.surface.copy(alpha = if (enhancedVisuals) 0.92f else 1f)
        },
        animationSpec = tween(durationMillis = 180),
        label = "message-bubble-color",
    )
    Column(
        modifier = Modifier.fillMaxWidth(),
        horizontalAlignment = if (isLocal) Alignment.End else Alignment.Start,
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth(0.84f)
                .widthIn(max = 520.dp)
                .clip(BubbleShape)
                .background(bubbleColor)
                .animateContentSize(animationSpec = tween(durationMillis = 180, easing = FastOutSlowInEasing))
                .padding(horizontal = 14.dp, vertical = 12.dp),
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
                        color = if (message.status != "ok") {
                            MaterialTheme.colorScheme.onErrorContainer
                        } else if (isLocal) {
                            MaterialTheme.colorScheme.onPrimaryContainer
                        } else {
                            MaterialTheme.colorScheme.onSurface
                        },
                    )
                    Text(
                        text = formatConversationTimestamp(message.createdAt),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }

                Text(
                    text = message.body,
                    style = MaterialTheme.typography.bodyLarge,
                    color = if (message.status != "ok") {
                        MaterialTheme.colorScheme.onErrorContainer
                    } else if (isLocal) {
                        MaterialTheme.colorScheme.onPrimaryContainer
                    } else {
                        MaterialTheme.colorScheme.onSurface
                    },
                )

                AnimatedVisibility(
                    visible = message.attachments.isNotEmpty(),
                    enter = fadeIn(tween(180)) + expandVertically(tween(220, easing = FastOutSlowInEasing)),
                    exit = fadeOut(tween(140)) + shrinkVertically(tween(180)),
                ) {
                    if (message.attachments.isNotEmpty()) {
                        Column(
                            modifier = Modifier.fillMaxWidth(),
                            verticalArrangement = Arrangement.spacedBy(4.dp),
                        ) {
                            Text(
                                text = attachmentCountLabel(message.attachments.size),
                                style = MaterialTheme.typography.labelLarge,
                                color = MaterialTheme.colorScheme.onSurface,
                            )
                            Text(
                                text = message.attachments.joinToString(", ") { it.fileName },
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                maxLines = 2,
                                overflow = TextOverflow.Ellipsis,
                            )
                        }
                    }
                }

                messageStatusLabel(message.status)?.let { status ->
                    InlineStatusBadge(
                        label = status,
                        tone = MaterialTheme.colorScheme.tertiary,
                    )
                }
        }
    }
}

@Composable
private fun EmptyState(
    title: String,
    body: String,
    actionLabel: String? = null,
    onAction: (() -> Unit)? = null,
) {
    Box(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        contentAlignment = Alignment.Center,
    ) {
        EmptyStateCard(
            title = title,
            body = body,
            actionLabel = actionLabel,
            onAction = onAction,
        )
    }
}

@Composable
private fun EmptyStateCard(
    title: String,
    body: String,
    actionLabel: String? = null,
    onAction: (() -> Unit)? = null,
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(PanelShape)
            .background(MaterialTheme.colorScheme.surface.copy(alpha = 0.86f))
            .padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
            Text(
                text = title,
                style = MaterialTheme.typography.titleLarge,
                color = MaterialTheme.colorScheme.onSurface,
                textAlign = TextAlign.Center,
            )
            Text(
                text = body,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center,
            )
            if (actionLabel != null && onAction != null) {
                FilledTonalButton(onClick = onAction) {
                    Text(actionLabel)
                }
            }
    }
}

@Composable
private fun DetailLine(
    label: String,
    value: String,
) {
    Column(verticalArrangement = Arrangement.spacedBy(3.dp)) {
        Text(
            text = label,
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(
            text = value,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurface,
        )
    }
}

@Composable
private fun StatusRow(
    title: String,
    value: String,
    tone: Color,
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text = title,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurface,
        )
        InlineStatusBadge(label = value, tone = tone)
    }
}

@Composable
private fun InlineStatusBadge(
    label: String,
    tone: Color,
) {
    Surface(
        shape = CircleShape,
        color = tone.copy(alpha = 0.14f),
    ) {
        Text(
            text = label,
            modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp),
            style = MaterialTheme.typography.labelMedium,
            color = tone,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
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
        else -> status.replace('-', ' ').replaceFirstChar {
            if (it.isLowerCase()) {
                it.titlecase(Locale.getDefault())
            } else {
                it.toString()
            }
        }
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

@Composable
private fun screenBackgroundBrush(enhanced: Boolean): Brush =
    if (enhanced) {
        Brush.linearGradient(
            colors = listOf(
                MaterialTheme.colorScheme.background,
                MaterialTheme.colorScheme.background,
                MaterialTheme.colorScheme.background,
            ),
        )
    } else {
        Brush.linearGradient(
            colors = listOf(
                MaterialTheme.colorScheme.background,
                MaterialTheme.colorScheme.background,
            ),
        )
    }

@Composable
private fun sectionCardBrush(enhanced: Boolean, accent: Color): Brush =
    if (enhanced) {
        Brush.linearGradient(
            colors = listOf(
                lerp(MaterialTheme.colorScheme.surface, accent, 0.04f).copy(alpha = 0.84f),
                lerp(MaterialTheme.colorScheme.surface, accent, 0.04f).copy(alpha = 0.84f),
            ),
        )
    } else {
        Brush.verticalGradient(
            colors = listOf(
                MaterialTheme.colorScheme.surface,
                MaterialTheme.colorScheme.surface,
            ),
        )
    }

@Composable
private fun threadRowBrush(enhanced: Boolean, selected: Boolean): Brush {
    val base = if (selected) {
        MaterialTheme.colorScheme.primaryContainer.copy(alpha = if (enhanced) 0.86f else 1f)
    } else {
        MaterialTheme.colorScheme.surface.copy(alpha = if (enhanced) 0.8f else 1f)
    }
    return if (enhanced) {
        Brush.linearGradient(
            colors = listOf(
                base,
                base,
            ),
        )
    } else {
        Brush.linearGradient(colors = listOf(base, base))
    }
}

@Composable
private fun surfaceRowBrush(enhanced: Boolean, accent: Color): Brush =
    if (enhanced) {
        Brush.linearGradient(
            colors = listOf(
                lerp(MaterialTheme.colorScheme.surface, accent, 0.035f).copy(alpha = 0.82f),
                lerp(MaterialTheme.colorScheme.surface, accent, 0.035f).copy(alpha = 0.82f),
            ),
        )
    } else {
        Brush.linearGradient(
            colors = listOf(
                MaterialTheme.colorScheme.surface,
                MaterialTheme.colorScheme.surface,
            ),
        )
    }

@Composable
private fun messageBubbleBrush(enhanced: Boolean, isLocal: Boolean, hasWarning: Boolean): Brush {
    val base = when {
        hasWarning -> MaterialTheme.colorScheme.errorContainer.copy(alpha = if (enhanced) 0.88f else 1f)
        isLocal -> MaterialTheme.colorScheme.primaryContainer.copy(alpha = if (enhanced) 0.88f else 1f)
        else -> MaterialTheme.colorScheme.surface.copy(alpha = if (enhanced) 0.84f else 1f)
    }
    return if (enhanced) {
        Brush.linearGradient(
            colors = listOf(
                base,
                base,
            ),
        )
    } else {
        Brush.linearGradient(colors = listOf(base, base))
    }
}

@Composable
private fun successTone(): Color = Color(0xFF2E8B57)
