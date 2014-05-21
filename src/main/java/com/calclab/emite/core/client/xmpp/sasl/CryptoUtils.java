package com.calclab.emite.core.client.xmpp.sasl;

/*
 * This is PBKDF2 (PKCS#5, RFC 2898), using HMAC and SHA-1.
 */

public class CryptoUtils {
	static int SHA1BITS = 160;
	public static final byte[] XOR(final byte[] a, final byte[] b) {
		// checkArgument(a.length == b.length, "Both arrays must be the same length");

		final byte[] r = new byte[a.length];
		for (int i = 0; i < a.length; i++) {
			r[i] = (byte) (a[i] ^ b[i]);
		}

		return r;
	}
	public static final byte[] XOR(final byte[] a, final byte b) {
		// checkArgument(a.length == b.length, "Both arrays must be the same length");

		final byte[] r = new byte[a.length];
		for (int i = 0; i < a.length; i++) {
			r[i] = (byte) (a[i] ^ b);
		}

		return r;
	}
	static public byte[] SHA1(byte[] input) {
		SHA1Digest h = new SHA1Digest();
		h.update(input, 0, input.length);
		byte[] output = new byte[SHA1BITS/8];
		h.doFinal(output, 0);
		return output;
	}
	static public byte[] HMAC(byte[] key, byte[] message) {
		// Steps here are from RFC 2104.
		// (1) append zeros.
		byte[] KE = new byte[64];
		GeneralDigest.arraycopy(KE, 0, key, 0, key.length);
		// (2)
		byte[] inner = XOR(KE, (byte)0x36);
		// (3) and (4)
		SHA1Digest h = new SHA1Digest();
		h.update(inner, 0, inner.length);
		h.update(message, 0, message.length);
		byte[] r = new byte[SHA1BITS/8];
		h.doFinal(r, 0);
		// Inner now contains H(K XOR ipad, text)
		// (5)
		byte[] outer = XOR(KE, (byte)0x5C);
		h = new SHA1Digest();
		// (6) / (7).
		h.update(outer, 0, outer.length);
		h.update(r, 0, r.length);
		h.doFinal(r, 0);
		return r;
	}
	static public byte[] PBKDF2(byte[] password, byte[] salt, int iterations) {
		// Limited PBKDF2 as described in RFC 5802.
		byte[] salted = new byte[salt.length + 4];
		GeneralDigest.arraycopy(salted, 0, salt, 0, salt.length);
		salted[salted.length - 1] = 0x01;
		byte[] Ux = HMAC(password, salted);
		byte[] out = new byte[Ux.length];
		out = XOR(out, Ux);
		for (int i = 1; i != iterations; ++i) {
			Ux = HMAC(password, Ux);
			out = XOR(out, Ux);
		}
		return out;
	}
}
