/*
 * ((e)) emite: A pure Google Web Toolkit XMPP library
 * Copyright (c) 2008-2011 The Emite development team
 * 
 * This file is part of Emite.
 *
 * Emite is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation, either version 3
 * of the License, or (at your option) any later version.
 *
 * Emite is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with Emite.  If not, see <http://www.gnu.org/licenses/>.
 */

package com.calclab.emite.core.client.xmpp.sasl;

import java.util.Arrays;
import java.util.Random;

import com.calclab.emite.core.client.xmpp.session.Credentials;

public final class ScramSHA1Client implements SASLManager.Mechanism {

	private static enum State {
		IR, START, AUTH, DONE, FAIL
	};

	private static final Random random = new Random();

	private String gs2hdr;
	private String cnonce;
	private String snonce;
	private byte[] salt;
	private int icount;
	private byte[] cacheSaltedPassword;

	private State state;
	
	private Credentials credentials;
	private DecoderRegistry decoders;
	
	String clientFirstMessageBare;
	byte[] authMessage;

	public ScramSHA1Client(final Credentials credentials, final DecoderRegistry decoders) {
		this.credentials = credentials;
		this.decoders = decoders;
		state = State.IR;
		gs2hdr = "n,,"; // no channel binding, no authzid
		final byte[] rnd = new byte[16];
		random.nextBytes(rnd);
		cnonce = new String(Base64Coder.encode(rnd));
		this.cacheSaltedPassword = null;
	}
	
	// Force a particular cnonce for testing.
	public void forceCnonce(final String cnonce) {
		this.cnonce = cnonce;
	}
	
	@Override
	public String getName() {
		return "SCRAM-SHA-1";
	}

	@Override
	public byte[] initialResponse() {
		/// checkState(state == State.IR);
		state = State.START;
		this.clientFirstMessageBare = "n=" + quote(credentials.getXmppUri().getNode()) + ",r=" + cnonce;
		return (gs2hdr + this.clientFirstMessageBare).getBytes();
	}

	@Override
	public byte[] nextResponse(byte[] challenge) {
		switch (state) {
		case IR:
			if (challenge != null) throw new SASLManager.UnexpectedChallenge("Challenge sent before IR");
			return initialResponse();
		case START:
			String[] bits = new String(challenge).split(",");
			for (String item : bits) {
				if (item.charAt(1) != '=') {
					throw new SASLManager.MalformedChallenge("Expected equals sign.");
				}
				switch (item.charAt(0)) {
				case 's':
					salt = Base64Coder.decode(item.substring(2));
					break;
				case 'r':
					snonce = item.substring(2);
					if (!snonce.startsWith(cnonce))
						throw new SASLManager.MalformedChallenge("Invalid server nonce");
					break;
				case 'i':
					icount = Integer.parseInt(item.substring(2));
					break;
				}
			}

			state = State.AUTH;
			String clientFinalMessage = "c=" + new String(Base64Coder.encode(gs2hdr.getBytes())) + ",r=" + snonce;
			return (clientFinalMessage + ",p=" + new String(Base64Coder.encode(clientProof(clientFinalMessage, new String(challenge))))).getBytes();
		case AUTH:
			state = State.FAIL;
			String[] bits2 = new String(challenge).split(",");
			for (String item : bits2) {
				if (item.charAt(1) != '=') {
					throw new SASLManager.MalformedChallenge("Expected equals sign.");
				}
				switch (item.charAt(0)) {
				case 'v':
					final byte[] serverSignature = Base64Coder.decode(item.substring(2));
					if (Arrays.equals(serverSignature, serverSignature()))
						state = State.DONE;
					break;
				}
			}
			
			state = State.DONE;
			return null;
		case DONE:
		case FAIL:
			if (challenge != null) throw new SASLManager.UnexpectedChallenge("Authentication is complete");
		default:
			throw new SASLManager.UnexpectedChallenge("Authentication is complete");
		}
	}
	
	@Override
	public boolean success(final byte[] verifier) {
		return (nextResponse(verifier) == null && state == State.DONE);
	}

	private String getPassword() {
		final PasswordDecoder decoder = decoders.getDecoder(credentials.getEncodingMethod());

		if (decoder == null)
			throw new RuntimeException("No password decoder found to convert from " + credentials.getEncodingMethod() + "to " + Credentials.ENCODING_BASE64);

		final String password = decoder.decode(credentials.getEncodingMethod(), credentials.getEncodedPassword());
		return password;
	}
	
	private final byte[] saltedPassword() {
		if (this.cacheSaltedPassword == null) {
			this.cacheSaltedPassword = CryptoUtils.PBKDF2(getPassword().getBytes(), salt, icount);
		}
		return this.cacheSaltedPassword;
	}

	private final byte[] clientProof(String clientFinal, String serverFirst) {
		final byte[] clientKey = CryptoUtils.HMAC(saltedPassword(), "Client Key".getBytes());
		final byte[] storedKey = CryptoUtils.SHA1(clientKey);
		this.authMessage = (clientFirstMessageBare + "," + serverFirst + "," + clientFinal).getBytes();
		final byte[] clientSignature = CryptoUtils.HMAC(storedKey, authMessage);
		return XOR(clientKey, clientSignature);
	}

	private final byte[] serverSignature() {
		final byte[] serverKey = CryptoUtils.HMAC(saltedPassword(), "Server Key".getBytes());
		return CryptoUtils.HMAC(serverKey, authMessage);
	}

	private static final String quote(final String input) {
		return input.replace("=", "=3D").replace(",", "=2C");
	}

	public static final byte[] XOR(final byte[] a, final byte[] b) {
		// checkArgument(a.length == b.length, "Both arrays must be the same length");

		final byte[] r = new byte[a.length];
		for (int i = 0; i < a.length; i++) {
			r[i] = (byte) (a[i] ^ b[i]);
		}

		return r;
	}

}
