package io.github.scisaga.loom.enrollment

import android.Manifest
import android.content.pm.PackageManager
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
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

@Composable
fun InviteScanner(
    onScanned: (String) -> Unit,
    onCancel: () -> Unit,
) {
    val context = LocalContext.current
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

    Box(
        modifier = Modifier.fillMaxWidth(),
        contentAlignment = Alignment.TopCenter,
    ) {
        Card(
            colors = CardDefaults.cardColors(containerColor = Color.Black),
            shape = RoundedCornerShape(20.dp),
            modifier = Modifier.widthIn(max = 560.dp).fillMaxWidth().testTag("invite-scanner"),
        ) {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                if (granted && !cameraFailed) {
                    BoxWithConstraints(
                        modifier = Modifier.fillMaxWidth().padding(start = 16.dp, top = 16.dp, end = 16.dp),
                        contentAlignment = Alignment.Center,
                    ) {
                        val edge = scannerViewportEdge(maxWidth)
                        Box(
                            modifier = Modifier
                                .size(edge)
                                .clip(RoundedCornerShape(18.dp))
                                .background(Color(0xFF111111))
                                .testTag("invite-scanner-preview"),
                        ) {
                            CameraPreview(
                                onScanned = onScanned,
                                onCameraError = { cameraFailed = true },
                                modifier = Modifier.fillMaxSize(),
                            )
                            Box(
                                modifier = Modifier
                                    .align(Alignment.Center)
                                    .fillMaxSize(0.72f)
                                    .border(2.dp, Color.White, RoundedCornerShape(16.dp))
                                    .testTag("invite-scanner-reticle"),
                            )
                        }
                    }
                    Text(
                        "将中控的一次性加入二维码放入方框。二维码不会写入相册或诊断。",
                        color = Color.White,
                        modifier = Modifier.padding(horizontal = 16.dp),
                    )
                } else if (!granted) {
                    Text(
                        "扫码需要相机权限；也可以返回后导入 .loom-invite 文件。",
                        color = Color.White,
                        modifier = Modifier.padding(20.dp),
                    )
                    Button(
                        onClick = { permission.launch(Manifest.permission.CAMERA) },
                        modifier = Modifier.padding(horizontal = 16.dp),
                    ) { Text("允许相机") }
                } else {
                    Text(
                        "无法启动相机。请返回并导入 .loom-invite 文件，或稍后重新打开扫码。",
                        color = Color.White,
                        modifier = Modifier.padding(20.dp).testTag("invite-camera-error"),
                    )
                }
                OutlinedButton(
                    onClick = onCancel,
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp).padding(bottom = 16.dp),
                ) { Text("取消") }
            }
        }
    }
}

internal fun scannerViewportEdge(available: Dp): Dp = minOf(available, 420.dp)

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
    val delivered = remember { AtomicBoolean(false) }
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
                            analyze(image)?.takeIf { delivered.compareAndSet(false, true) }?.let { value ->
                                ContextCompat.getMainExecutor(context).execute { currentOnScanned(value) }
                            }
                        }
                    }
                analysis = analysisUseCase
                provider?.unbindAll()
                provider?.bindToLifecycle(lifecycleOwner, CameraSelector.DEFAULT_BACK_CAMERA, previewUseCase, analysisUseCase)
            }.onFailure { currentOnCameraError() }
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
