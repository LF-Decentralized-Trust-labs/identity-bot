package com.example.identity_agent_ui

import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

class MainActivity: FlutterActivity() {
    private val CHANNEL = "com.identityagent/mobilecore"

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)

        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CHANNEL).setMethodCallHandler { call, result ->
            when (call.method) {
                "startServer" -> {
                    try {
                        val dataDir = call.argument<String>("dataDir")
                            ?: filesDir.resolve("identity_agent_data").absolutePath
                        val port = call.argument<Int>("port") ?: 8642
                        // This app serves an individual. There is no
                        // open-source app for an organization and there is not
                        // going to be, so this is settled at build time rather
                        // than asked. It decides who may witness and watch for
                        // this agent: peers are of the same kind, and an agent
                        // that has not been told enrols none.
                        mobilecore.Mobilecore.declareEntityType("individual")
                        mobilecore.Mobilecore.startServer(dataDir, port.toLong())
                        result.success(mapOf("status" to "started", "port" to port))
                    } catch (e: Exception) {
                        result.error("START_FAILED", e.message, null)
                    }
                }
                "stopServer" -> {
                    try {
                        mobilecore.Mobilecore.stopServer()
                        result.success(mapOf("status" to "stopped"))
                    } catch (e: Exception) {
                        result.error("STOP_FAILED", e.message, null)
                    }
                }
                "isRunning" -> {
                    try {
                        val running = mobilecore.Mobilecore.isRunning()
                        result.success(running)
                    } catch (e: Exception) {
                        result.success(false)
                    }
                }
                "getHealth" -> {
                    try {
                        val health = mobilecore.Mobilecore.getHealth()
                        result.success(health)
                    } catch (e: Exception) {
                        result.error("HEALTH_FAILED", e.message, null)
                    }
                }
                "getPort" -> {
                    try {
                        val port = mobilecore.Mobilecore.getPort()
                        result.success(port.toInt())
                    } catch (e: Exception) {
                        result.success(0)
                    }
                }
                "getDataDir" -> {
                    result.success(filesDir.resolve("identity_agent_data").absolutePath)
                }
                else -> result.notImplemented()
            }
        }
    }
}
