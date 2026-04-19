package com.notrus.android

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.enableEdgeToEdge
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.appcompat.app.AppCompatActivity
import androidx.compose.runtime.SideEffect
import com.notrus.android.ui.NotrusAndroidApp
import com.notrus.android.ui.NotrusViewModel
import com.notrus.android.ui.theme.NotrusAndroidTheme

class MainActivity : AppCompatActivity() {
    private val viewModel: NotrusViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            NotrusAndroidTheme(
                themeKey = viewModel.state.colorThemePreset,
                themeModeKey = viewModel.state.themeMode,
            ) {
                SideEffect {
                    if (viewModel.state.privacyModeEnabled) {
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
    }
}
