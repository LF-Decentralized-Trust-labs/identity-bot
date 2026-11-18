package org.identityagent.login_flutter

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.io.ByteArrayOutputStream
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.ProviderException
import java.security.Signature
import java.security.cert.Certificate
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

/**
 * The Android side of the hardware key (ADR-072 section 4, Amendment 3): a P-256 key
 * made in the Android Keystore, limited to signing, whose key attestation names the
 * ask's challenge. Android fixes the attestation challenge when the key is
 * generated, so [attestNewKey] makes a new key under the label each time, and the
 * sign-in then names that key.
 *
 * What the Identity Agent checks of the evidence (Android Key Attestation to a pinned
 * Google root, the attested package and signing certificates being the owner's) is
 * its to decide; this only produces it: each certificate of the chain, DER, preceded
 * by its length as 4 bytes big-endian (`InstalledAppKeyProof`).
 *
 * Not run in this repository's tests (no device); see the package README.
 */
object HardwareKey {
    private const val PROVIDER = "AndroidKeyStore"

    private fun store(): KeyStore = KeyStore.getInstance(PROVIDER).apply { load(null) }

    private fun private_(label: String): PrivateKey =
        store().getKey(label, null) as? PrivateKey
            ?: throw IllegalStateException("no key named $label")

    private fun point(cert: Certificate): ByteArray {
        val w = (cert.publicKey as ECPublicKey).w
        fun fixed(v: java.math.BigInteger): ByteArray {
            val b = v.toByteArray().let { if (it.size > 32) it.copyOfRange(it.size - 32, it.size) else it }
            return ByteArray(32 - b.size) + b
        }
        return byteArrayOf(4) + fixed(w.affineX) + fixed(w.affineY)
    }

    /** The key [label] names, or null when there is none yet: a key is made for an ask. */
    fun publicPoint(label: String): ByteArray? {
        val ks = store()
        return if (ks.containsAlias(label)) point(ks.getCertificate(label)) else null
    }

    private fun generate(label: String, challenge: ByteArray) {
        fun spec(strongBox: Boolean) = KeyGenParameterSpec.Builder(label, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            // SHA-256 for every call's proof; NONE so the key can sign the statement's digest as it is.
            .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_NONE)
            .apply {
                setAttestationChallenge(challenge)
                if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) setIsStrongBoxBacked(true)
            }
            .build()
        store().deleteEntry(label)
        for (strongBox in listOf(true, false)) {
            try {
                KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, PROVIDER)
                    .apply { initialize(spec(strongBox)) }.generateKeyPair()
                return
            } catch (e: ProviderException) {
                // StrongBoxUnavailableException exists from API 28 and is a ProviderException:
                // it alone falls through to the TEE. Below API 28 StrongBox is never asked for,
                // and the class is not named where it does not exist.
                if (!strongBox || Build.VERSION.SDK_INT < Build.VERSION_CODES.P || e !is StrongBoxUnavailableException) throw e
            }
        }
    }

    /** A new key under [label] for [challenge]: its public point and its attestation chain. */
    fun attestNewKey(label: String, challenge: ByteArray): Pair<ByteArray, ByteArray> {
        generate(label, challenge)
        val chain = store().getCertificateChain(label)
        val out = ByteArrayOutputStream()
        for (c in chain) {
            val der = c.encoded
            out.write(byteArrayOf((der.size ushr 24).toByte(), (der.size ushr 16).toByte(), (der.size ushr 8).toByte(), der.size.toByte()))
            out.write(der)
        }
        return Pair(point(chain[0]), out.toByteArray())
    }

    /** ECDSA over SHA-256 of [message], ASN.1 DER. */
    fun signCall(label: String, message: ByteArray): ByteArray =
        Signature.getInstance("SHA256withECDSA").apply { initSign(private_(label)); update(message) }.sign()

    /** ECDSA over [digest] as it is (the SHA-256 of the sign-in statement), ASN.1 DER. */
    fun signStatement(label: String, digest: ByteArray): ByteArray =
        Signature.getInstance("NONEwithECDSA").apply { initSign(private_(label)); update(digest) }.sign()
}
