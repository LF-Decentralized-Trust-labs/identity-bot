package com.example.identity_agent_ui

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.KeyFactory
import java.security.PrivateKey

/**
 * Asks this phone's Keystore whether it can protect a key, by making one.
 *
 * The core cannot do this itself. On macOS it asks the Security framework and
 * on Windows the platform crypto provider, both directly from Go; the Android
 * Keystore is a Java API with no path to it from Go, so the app asks and reports
 * what it found. The core still owns what the answer means.
 *
 * USABLE IS PROVEN, NEVER INFERRED. The core's contract is explicit that "a key
 * was actually created in the hardware and discarded. Nothing short of doing the
 * thing counts." So this generates a real EC key, asks the Keystore where it
 * ended up, and deletes it. Reading Build.VERSION, a feature flag or a device
 * model would be the guess the whole mechanism exists to stop — and it would be
 * wrong in both directions, because manufacturers ship the same model with and
 * without StrongBox.
 *
 * ABSENT NEEDS POSITIVE EVIDENCE. An exception nobody recognised is "unknown".
 * Telling somebody their phone has no security hardware when the truth is that a
 * call failed is a false statement about their property, and it sends them to
 * buy what they may already own.
 */
object KeystoreProbe {

    /** What the probe found, in the four fields the core stores. */
    data class Result(
        val status: String,
        val kind: String,
        val reason: String,
        val detail: String,
    )

    private const val ALIAS = "org.identitybot.keyprotection.probe"

    fun run(): Result {
        // StrongBox first: it is the stronger of the two, and a phone that has it
        // should be reported as having it.
        //
        // ANY failure here falls through to the TEE rather than ending the probe.
        // A phone without StrongBox is supposed to throw
        // StrongBoxUnavailableException, and many do — but vendors are not
        // consistent, and some wrap it in a ProviderException or throw something
        // else entirely. Treating an unrecognised StrongBox failure as the final
        // answer would report "unknown" on a phone whose ordinary TEE works
        // perfectly, which is most of them.
        //
        // That is not hypothetical. The first run of this probe threw a
        // ClassCastException inside the StrongBox attempt on Android 12, and an
        // earlier version of this function returned unknown then and there
        // without ever asking the TEE.
        var strongBoxDetail = ""
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            when (val strongBox = attempt(useStrongBox = true)) {
                is Attempt.Made -> return usable("android_strongbox", strongBox.securityLevel)
                is Attempt.NoStrongBox -> Unit
                is Attempt.Failed -> strongBoxDetail = strongBox.detail
            }
        }

        return when (val tee = attempt(useStrongBox = false)) {
            is Attempt.Made -> {
                if (tee.insideSecureHardware) {
                    usable("android_tee", tee.securityLevel)
                } else {
                    // The Keystore made a key and told us it is NOT in secure
                    // hardware. That is the operating system stating there is no
                    // hardware-backed keystore here, which is the positive
                    // evidence the core requires before anything is called absent.
                    Result(
                        status = "absent",
                        kind = "",
                        reason = "keystore_is_software_backed",
                        detail = "the Keystore created the key outside secure hardware (" +
                            tee.securityLevel + "), so a key kept here could be copied off the device",
                    )
                }
            }
            is Attempt.NoStrongBox ->
                unknown("strongbox_unavailable_without_strongbox_requested",
                    "the Keystore reported StrongBox unavailable for a key that did not ask for it")
            is Attempt.Failed -> unknown(
                "keystore_probe_failed",
                // Both failures, when there were two. Whoever diagnoses this
                // needs to know whether StrongBox alone failed or the Keystore
                // refused everything, and the two have different remedies.
                if (strongBoxDetail.isEmpty()) tee.detail
                else "tee: " + tee.detail + "; strongbox: " + strongBoxDetail,
            )
        }
    }

    private sealed class Attempt {
        data class Made(val insideSecureHardware: Boolean, val securityLevel: String) : Attempt()
        object NoStrongBox : Attempt()
        data class Failed(val detail: String) : Attempt()
    }

    private fun attempt(useStrongBox: Boolean): Attempt {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        try {
            // Deleting first rather than reusing: a key left by an earlier run
            // would make this report where THAT key went, which may not be where
            // one would go now — a phone can be updated, and StrongBox can start
            // or stop being available under the same alias.
            runCatching { keyStore.deleteEntry(ALIAS) }

            val spec = KeyGenParameterSpec.Builder(
                ALIAS,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
            )
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAlgorithmParameterSpec(java.security.spec.ECGenParameterSpec("secp256r1"))
                // No user authentication required. This is a probe, not a key
                // anything will use, and demanding a fingerprint to answer a
                // question nobody asked would be its own defect.
                .setUserAuthenticationRequired(false)
                .apply {
                    if (useStrongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                        setIsStrongBoxBacked(true)
                    }
                }
                .build()

            val generator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore",
            )
            generator.initialize(spec)
            generator.generateKeyPair()

            // PrivateKey, never ECPrivateKey. A key that lives in the Keystore
            // is returned as an opaque AndroidKeyStorePrivateKey which does NOT
            // implement ECPrivateKey — because ECPrivateKey exposes the private
            // scalar, and a key inside secure hardware has no such thing to give.
            // Casting to it throws, and the throw looks exactly like a probe
            // failure on a phone whose hardware is perfect. Observed on Android
            // 12: "android.security.keystore2.AndroidKeyStoreECPrivateKey cannot
            // be cast to java.security.interfaces.ECPrivateKey".
            val entry = keyStore.getKey(ALIAS, null) as PrivateKey
            val info = KeyFactory.getInstance(entry.algorithm, "AndroidKeyStore")
                .getKeySpec(entry, KeyInfo::class.java)

            return Attempt.Made(
                insideSecureHardware = securityLevelIsHardware(info),
                securityLevel = describeSecurityLevel(info),
            )
        } catch (e: StrongBoxUnavailableException) {
            return Attempt.NoStrongBox
        } catch (e: Throwable) {
            return Attempt.Failed(e.javaClass.simpleName + ": " + (e.message ?: "no message"))
        } finally {
            // Nothing is left behind. A probe that accumulated a key per launch
            // would be a probe nobody could run twice.
            runCatching { keyStore.deleteEntry(ALIAS) }
        }
    }

    @Suppress("DEPRECATION")
    private fun securityLevelIsHardware(info: KeyInfo): Boolean =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            info.securityLevel != KeyProperties.SECURITY_LEVEL_SOFTWARE
        } else {
            info.isInsideSecureHardware
        }

    @Suppress("DEPRECATION")
    private fun describeSecurityLevel(info: KeyInfo): String =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            when (info.securityLevel) {
                KeyProperties.SECURITY_LEVEL_STRONGBOX -> "strongbox"
                KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> "trusted_environment"
                KeyProperties.SECURITY_LEVEL_SOFTWARE -> "software"
                else -> "level_" + info.securityLevel
            }
        } else {
            if (info.isInsideSecureHardware) "secure_hardware" else "software"
        }

    private fun usable(kind: String, securityLevel: String) = Result(
        status = "usable",
        kind = kind,
        reason = "",
        detail = "a key was created in the keystore and discarded (" + securityLevel + ")",
    )

    private fun unknown(reason: String, detail: String) = Result(
        status = "unknown",
        kind = "",
        reason = reason,
        detail = detail,
    )
}
