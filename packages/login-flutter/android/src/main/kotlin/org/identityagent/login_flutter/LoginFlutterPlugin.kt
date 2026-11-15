package org.identityagent.login_flutter

import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel

/** The channel `MethodChannelHardwareKey` (lib/src/hardware_key.dart) speaks. */
class LoginFlutterPlugin : FlutterPlugin, MethodChannel.MethodCallHandler {
    private var channel: MethodChannel? = null

    override fun onAttachedToEngine(b: FlutterPlugin.FlutterPluginBinding) {
        channel = MethodChannel(b.binaryMessenger, "org.identityagent.login_flutter/hardware_key").also { it.setMethodCallHandler(this) }
    }

    override fun onDetachedFromEngine(b: FlutterPlugin.FlutterPluginBinding) {
        channel?.setMethodCallHandler(null)
        channel = null
    }

    override fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
        try {
            val label = call.argument<String>("label") ?: return result.error("bad_args", "no label", null)
            when (call.method) {
                "publicPoint" -> result.success(HardwareKey.publicPoint(label))
                "attestNewKey" -> {
                    val (point, evidence) = HardwareKey.attestNewKey(label, call.argument<ByteArray>("challenge")!!)
                    result.success(mapOf("point" to point, "evidence" to evidence))
                }
                "sign" -> result.success(HardwareKey.sign(label, call.argument<ByteArray>("message")!!))
                "signStatement" -> result.success(HardwareKey.signStatement(label, call.argument<ByteArray>("digest")!!))
                else -> result.notImplemented()
            }
        } catch (e: Exception) {
            result.error("hardware", e.message ?: e.javaClass.simpleName, null)
        }
    }
}
