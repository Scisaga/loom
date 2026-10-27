package io.github.scisaga.loom.enrollment

import android.Manifest
import android.content.pm.PackageManager
import android.view.ViewGroup
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.IconButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.window.DialogWindowProvider
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

private val ScannerGreen = Color(0xFF239B68)

@Composable
fun InviteScanner(
    onScanned: (String) -> Unit,
    onCancel: () -> Unit,
) {
    val context = LocalContext.current
    val currentOnCancel by rememberUpdatedState(onCancel)
    val currentOnScanned by rememberUpdatedState(onScanned)
    val finished = remember { AtomicBoolean(false) }
    val dismiss: () -> Unit = {
        if (finished.compareAndSet(false, true)) currentOnCancel()
    }
    DisposableEffect(finished) {
        onDispose { finished.set(true) }
    }
    var granted by remember {
        mutableStateOf(ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED)
    }
    var cameraFailed by remember { mutableStateOf(false) }
    val permission = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) {
        granted = it
        if (it) cameraFailed = false
    }
    LaunchedEffect(Unit) {
        if (!granted) permission.launch(Manifest.permission.CAMERA)
    }

    Dialog(
        onDismissRequest = dismiss,
        // Keep real window constraints: this Compose version measures the whole
        // display when platform width is disabled, even if system bars clip it.
        properties = DialogProperties(decorFitsSystemWindows = false),
    ) {
        val window = (LocalView.current.parent as DialogWindowProvider).window
        SideEffect {
            // Match content constraints to the actual window, including system-bar clipping.
            window.setLayout(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT)
            window.setDimAmount(0.32f)
        }
        BoxWithConstraints(
            modifier = Modifier
                .fillMaxSize()
                .windowInsetsPadding(WindowInsets.safeDrawing)
                .pointerInput(Unit) { detectTapGestures { dismiss() } }
                .padding(24.dp)
                .testTag("invite-scanner-backdrop"),
            contentAlignment = Alignment.Center,
        ) {
            val edge = scannerViewportEdge(maxWidth, maxHeight)
            Box(
                modifier = Modifier
                    .size(edge)
                    .clip(RoundedCornerShape(18.dp))
                    .background(Color(0xFF111111))
                    .pointerInput(Unit) { detectTapGestures { } }
                    .semantics { contentDescription = "扫描加入二维码" }
                    .testTag("invite-scanner"),
            ) {
                if (granted && !cameraFailed) {
                    CameraPreview(
                        onScanned = { value ->
                            if (finished.compareAndSet(false, true)) currentOnScanned(value)
                        },
                        onCameraError = { if (!finished.get()) cameraFailed = true },
                        modifier = Modifier.fillMaxSize().testTag("invite-scanner-preview"),
                    )
                    Box(
                        modifier = Modifier
                            .align(Alignment.Center)
                            .fillMaxSize(0.72f)
                            .border(2.dp, ScannerGreen, RoundedCornerShape(16.dp))
                            .testTag("invite-scanner-reticle"),
                    )
                    Text(
                        "将加入二维码放入方框",
                        color = Color.White,
                        fontSize = 13.sp,
                        textAlign = TextAlign.Center,
                        modifier = Modifier
                            .align(Alignment.BottomCenter)
                            .fillMaxWidth()
                            .background(Color.Black.copy(alpha = 0.65f))
                            .padding(12.dp),
                    )
                } else {
                    Column(
                        modifier = Modifier.align(Alignment.Center).padding(24.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp),
                        horizontalAlignment = Alignment.CenterHorizontally,
                    ) {
                        Text(
                            if (cameraFailed) "无法启动相机，请关闭后重试或导入邀请文件。"
                            else "扫码需要相机权限，也可以关闭后导入邀请文件。",
                            color = Color.White,
                            fontSize = 14.sp,
                            textAlign = TextAlign.Center,
                            modifier = Modifier.testTag(if (cameraFailed) "invite-camera-error" else "invite-camera-permission"),
                        )
                        if (!granted) {
                            Button(
                                onClick = { permission.launch(Manifest.permission.CAMERA) },
                                colors = ButtonDefaults.buttonColors(containerColor = ScannerGreen),
                            ) { Text("允许相机") }
                        }
                    }
                }
                IconButton(
                    onClick = dismiss,
                    modifier = Modifier
                        .align(Alignment.TopEnd)
                        .padding(8.dp)
                        .background(Color.Black.copy(alpha = 0.6f), CircleShape)
                        .semantics { contentDescription = "关闭扫码" }
                        .testTag("close-invite-scanner"),
                ) {
                    Text("×", color = Color.White, fontSize = 28.sp)
                }
            }
        }
    }
}

internal fun scannerViewportEdge(availableWidth: Dp, availableHeight: Dp = Dp.Infinity): Dp =
    minOf(availableWidth, availableHeight, 420.dp)

@Composable
private fun CameraPreview(
    onScanned: (String) -> Unit,
    onCameraError: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    val previewView = remember {
        PreviewView(context).apply {
            implementationMode = PreviewView.ImplementationMode.COMPATIBLE
            scaleType = PreviewView.ScaleType.FILL_CENTER
        }
    }
    val currentOnScanned by rememberUpdatedState(onScanned)
    val currentOnCameraError by rememberUpdatedState(onCameraError)

    AndroidView(factory = { previewView }, modifier = modifier)
    DisposableEffect(lifecycleOwner, previewView) {
        val disposed = AtomicBoolean(false)
        val analyzerExecutor = Executors.newSingleThreadExecutor { runnable ->
            Thread(runnable, "loom-invite-scanner").apply { isDaemon = true }
        }
        val providerFuture = ProcessCameraProvider.getInstance(context)
        var provider: ProcessCameraProvider? = null
        var cameraPreview: Preview? = null
        var analysis: ImageAnalysis? = null
        providerFuture.addListener({
            if (disposed.get()) return@addListener
            runCatching {
                provider = providerFuture.get()
                val previewUseCase = Preview.Builder().build().also {
                    it.surfaceProvider = previewView.surfaceProvider
                }
                cameraPreview = previewUseCase
                val analysisUseCase = ImageAnalysis.Builder()
                    .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                    .build()
                    .also { useCase ->
                        useCase.setAnalyzer(analyzerExecutor) { image ->
                            analyze(image)?.let { value ->
                                ContextCompat.getMainExecutor(context).execute {
                                    if (!disposed.get()) currentOnScanned(value)
                                }
                            }
                        }
                    }
                analysis = analysisUseCase
                provider?.bindToLifecycle(lifecycleOwner, CameraSelector.DEFAULT_BACK_CAMERA, previewUseCase, analysisUseCase)
            }.onFailure { if (!disposed.get()) currentOnCameraError() }
        }, ContextCompat.getMainExecutor(context))

        onDispose {
            disposed.set(true)
            analysis?.clearAnalyzer()
            analysis?.let { provider?.unbind(it) }
            cameraPreview?.let { provider?.unbind(it) }
            analyzerExecutor.shutdownNow()
        }
    }
}

private fun analyze(image: ImageProxy): String? = try {
    val (luma, width, height) = rotatedLuma(image)
    val source = com.google.zxing.PlanarYUVLuminanceSource(
        luma,
        width,
        height,
        0,
        0,
        width,
        height,
        false,
    )
    QRCodeReader().decode(
        BinaryBitmap(HybridBinarizer(source)),
        mapOf(DecodeHintType.CHARACTER_SET to "UTF-8", DecodeHintType.TRY_HARDER to true),
    ).text
} catch (_: Exception) {
    null
} finally {
    image.close()
}

private data class Luma(val bytes: ByteArray, val width: Int, val height: Int)

private fun rotatedLuma(image: ImageProxy): Luma {
    val width = image.width
    val height = image.height
    val plane = image.planes[0]
    val source = plane.buffer.duplicate()
    val rowStride = plane.rowStride
    val pixelStride = plane.pixelStride
    val compact = ByteArray(width * height)
    for (row in 0 until height) {
        for (column in 0 until width) {
            compact[row * width + column] = source.get(row * rowStride + column * pixelStride)
        }
    }
    return when (image.imageInfo.rotationDegrees) {
        90 -> {
            val rotated = ByteArray(compact.size)
            for (y in 0 until height) for (x in 0 until width) {
                rotated[x * height + (height - y - 1)] = compact[y * width + x]
            }
            Luma(rotated, height, width)
        }
        180 -> Luma(compact.reversedArray(), width, height)
        270 -> {
            val rotated = ByteArray(compact.size)
            for (y in 0 until height) for (x in 0 until width) {
                rotated[(width - x - 1) * height + y] = compact[y * width + x]
            }
            Luma(rotated, height, width)
        }
        else -> Luma(compact, width, height)
    }
}
