package com.calclab.emite.core.client.xmpp.sasl;

import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.macs.HMac;

/*
 * This is PBKDF2 (PKCS#5, RFC 2898), using HMAC and SHA-1.
 */

public class CryptoUtils {
	static int SHA1BITS = 160;
	static public byte[] PBKDF2(byte[] password, byte[] salt, int iterations) {
		PBEParametersGenerator gen = new PKCS5S2ParametersGenerator();
		gen.init(password,  salt,  iterations);
		KeyParameter k = (KeyParameter)gen.generateDerivedParameters(SHA1BITS);
		return k.getKey();
	}
	static public byte[] SHA1(byte[] input) {
		SHA1Digest h = new SHA1Digest();
		h.update(input, 0, input.length);
		byte[] output = new byte[SHA1BITS/8];
		h.doFinal(output, 0);
		return output;
	}
	static public byte[] HMAC(byte[] key, byte[] message) {
		HMac h = new HMac(new SHA1Digest());
		h.init(new KeyParameter(key));
		byte[] output = new byte[SHA1BITS];
		h.update(message, 0, message.length);
		h.doFinal(output,  0);
		return output;
	}
}
