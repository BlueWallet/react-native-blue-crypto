package com.reactlibrary;

import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import com.facebook.react.bridge.Callback

class BlueCryptoModule(private val reactContext: ReactApplicationContext) : ReactContextBaseJavaModule(reactContext) {

    override public fun getName(): String {
        return "BlueCrypto";
    }

    @ReactMethod
    fun scrypted(passphrase: String, salt: String, N: Int, r: Int, p: Int, dkLen: Int, callback: Callback) {
        fun String.byteArrayFromHexString()=this.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        fun ByteArray.toHexString()=this.joinToString(""){ String.format("%02X",(it.toInt() and 0xFF)) }

        var passphraseBytes = passphrase.byteArrayFromHexString();
        var saltBytes = salt.byteArrayFromHexString();

        val hashed = SCrypt.scrypt(passphraseBytes, saltBytes, N, r, p, dkLen);
        callback.invoke(hashed.toHexString());
    }
}
