package com.notrus.android

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.enableEdgeToEdge
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.compose.runtime.SideEffect
import com.notrus.android.notifications.NotrusNotificationCenter
import com.notrus.android.ui.NotrusAndroidApp
import com.notrus.android.ui.NotrusViewModel
import com.notrus.android.ui.theme.NotrusAndroidTheme

class MainActivity : AppCompatActivity() {
    private val viewModel: NotrusViewModel by viewModels()
    private val notificationPermissionLauncher =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
            viewModel.onNotificationPermissionResult(granted)
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            NotrusAndroidTheme(
                themeKey = viewModel.state.colorThemePreset,
                themeModeKey = viewModel.state.themeMode,
            ) {
                SideEffect {
                    val shouldProtectWindow =
                        viewModel.state.privacyModeEnabled ||
                            viewModel.state.vaultLocked ||
                            viewModel.state.currentIdentity != null
                    if (shouldProtectWindow) {
                        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
                    } else {
                        window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
                    }
                }
                NotrusAndroidApp(
                    state = viewModel.state,
                    viewModel = viewModel,
                    activity = this,
                )
            }
        }
        handleLaunchIntent(intent)
    }

    override fun onStart() {
        super.onStart()
        viewModel.onAppForegroundChanged(true)
        requestNotificationPermissionIfNeeded()
    }

    override fun onStop() {
        viewModel.onAppForegroundChanged(false)
        super.onStop()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleLaunchIntent(intent)
    }

    private fun handleLaunchIntent(intent: Intent?) {
        val incoming = intent ?: return
        viewModel.openThreadFromNotification(
            threadId = incoming.getStringExtra(NotrusNotificationCenter.EXTRA_THREAD_ID),
            identityId = incoming.getStringExtra(NotrusNotificationCenter.EXTRA_IDENTITY_ID),
        )
    }

    private fun requestNotificationPermissionIfNeeded() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
            return
        }
        if (!viewModel.state.notificationsEnabled) {
            return
        }
        val granted = ContextCompat.checkSelfPermission(
            this,
            Manifest.permission.POST_NOTIFICATIONS,
        ) == PackageManager.PERMISSION_GRANTED
        if (!granted) {
            notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }
}
