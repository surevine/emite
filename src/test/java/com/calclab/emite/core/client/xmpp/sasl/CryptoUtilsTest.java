package com.calclab.emite.core.client.xmpp.sasl;

import static org.junit.Assert.assertTrue;
import org.junit.Test;


public class CryptoUtilsTest {
	// Take a byte[] and produce a hex string of the form found in draft-josefsson-pbkdf2-test-vectors-00, except with an additional terminating space.
	final static char[] hex = "0123456789abcdef".toCharArray();
	static String bytesToHex(byte[] bytes) {
		char[] out = new char[bytes.length * 3];
		for (int j = 0; j != bytes.length; ++j) {
			int v = bytes[j] & 0xFF;
			out[(j * 3)] = hex[v >>> 4];
			out[(j * 3) + 1] = hex[v & 0x0F];
			out[(j * 3) + 2] = ' ';
		}
		return new String(out);
	}
	
	@Test
	public void josefssonTestVectors() {
		String tmp = bytesToHex(CryptoUtils.PBKDF2("password".getBytes(), "salt".getBytes(), 1));
		assertTrue(tmp.equals("0c 60 c8 0f 96 1f 0e 71 f3 a9 b5 24 af 60 12 06 2f e0 37 a6 "));
		assertTrue(bytesToHex(CryptoUtils.PBKDF2("password".getBytes(), "salt".getBytes(), 2)).equals("ea 6c 01 4d c7 2d 6f 8c cd 1e d9 2a ce 1d 41 f0 d8 de 89 57 "));
		assertTrue(bytesToHex(CryptoUtils.PBKDF2("password".getBytes(), "salt".getBytes(), 4096)).equals("4b 00 79 01 b7 65 48 9a be ad 49 d9 26 f7 21 d0 65 a4 29 c1 "));
		// assertTrue(bytesToHex(CryptoUtils.PBKDF2("password".getBytes(), "salt".getBytes(), 16777216)).equals("ee fe 3d 61 cd 4d a4 e4 e9 94 5b 3d 6b a2 15 8c 26 34 e9 84 "));
		// Above is nightmarishly long to run.
	}
}
