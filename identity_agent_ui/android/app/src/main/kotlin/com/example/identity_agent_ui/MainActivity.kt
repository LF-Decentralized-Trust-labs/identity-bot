package com.example.identity_agent_ui

import android.util.Log
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

                        // What protects a key on this phone. The core cannot
                        // ask: the Keystore is a Java API and there is no path
                        // to it from Go, so the app probes it and reports what
                        // it found. Before startServer, like the line above.
                        //
                        // NOT OPTIONAL, AND THIS IS THE REFERENCE FOR ANYONE
                        // EMBEDDING THE CORE. An app that stays quiet is treated
                        // as one that never looked, which is honest and which
                        // refuses to put a root key on the machine — so a phone
                        // with perfectly good hardware cannot found an identity
                        // until its app asks the Keystore and says so.
                        //
                        // A failure here must not stop the agent. Not knowing is
                        // a real answer the core handles, and an app that crashed
                        // instead would turn a cautious answer into no agent.
                        try {
                            val probe = KeystoreProbe.run()
                            Log.i("KeystoreProbe", "status=${probe.status} kind=${probe.kind} " +
                                "reason=${probe.reason} detail=${probe.detail}")
                            mobilecore.Mobilecore.declareHardwareKeyProtection(
                                probe.status, probe.kind, probe.reason, probe.detail,
                            )
                        } catch (e: Throwable) {
                            Log.w("KeystoreProbe", "the probe threw", e)
                            mobilecore.Mobilecore.declareHardwareKeyProtection(
                                "unknown", "", "probe_threw",
                                e.javaClass.simpleName + ": " + (e.message ?: "no message"),
                            )
                        }

                        // The secret that makes this app, and no other app on
                        // the phone, the owner of the core it starts. The Dart
                        // side chose it and sends it with every request; a bad
                        // one throws, and the start is reported as failed.
                        call.argument<String>("localOwnerSecret")?.let {
                            mobilecore.Mobilecore.declareLocalOwnerSecret(it)
                        }

                        mobilecore.Mobilecore.startServer(dataDir, port.toLong())
                        // The port the core actually bound, not the one asked
                        // for: it takes the next free one when that is held, and
                        // the app must talk to it there, never to whoever holds
                        // the one it asked for.
                        result.success(mapOf("status" to "started",
                            "port" to mobilecore.Mobilecore.getPort().toInt()))
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
