package com.notrus.android

import android.os.Bundle
import androidx.activity.enableEdgeToEdge
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.appcompat.app.AppCompatActivity
import com.notrus.android.ui.NotrusAndroidApp
import com.notrus.android.ui.NotrusViewModel
import com.notrus.android.ui.theme.NotrusAndroidTheme

class MainActivity : AppCompatActivity() {
    private val viewModel: NotrusViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            NotrusAndroidTheme {
                NotrusAndroidApp(
                    state = viewModel.state,
                    viewModel = viewModel,
                    activity = this,
                )
            }
        }
    }
}
