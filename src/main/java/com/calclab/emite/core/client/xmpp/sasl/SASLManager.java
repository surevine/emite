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

import java.util.ArrayList;
import java.util.List;

import com.calclab.emite.core.client.conn.StanzaEvent;
import com.calclab.emite.core.client.conn.StanzaHandler;
import com.calclab.emite.core.client.conn.XmppConnection;
import com.calclab.emite.core.client.events.EmiteEventBus;
import com.calclab.emite.core.client.packet.IPacket;
import com.calclab.emite.core.client.packet.MatcherFactory;
import com.calclab.emite.core.client.packet.Packet;
import com.calclab.emite.core.client.xmpp.session.Credentials;
import com.google.inject.Inject;
import com.google.inject.Singleton;

@Singleton
public class SASLManager {
	interface Mechanism {
		byte[] initialResponse();
		byte[] nextResponse(byte[] challenge);
		boolean success(byte[] additionalData);
		String getName();
	}
	public static class UnexpectedChallenge extends RuntimeException {
		private static final long serialVersionUID = 1891035940672367035L;
		public UnexpectedChallenge(final String msg) { super(msg); }
	}
	public static class NoMechanisms extends RuntimeException {
		private static final long serialVersionUID = 8036427387321214035L;
		public NoMechanisms(final String msg) { super(msg); }
	}
	public static class MutualAuthFailure extends RuntimeException {
		private static final long serialVersionUID = 7510053687939485562L;
		public MutualAuthFailure(final String msg) { super(msg); }
	}
	public static class MalformedChallenge extends RuntimeException {
		private static final long serialVersionUID = -4273947057481759221L;
		public MalformedChallenge(final String msg) { super(msg); }
	}
	
	private static final String SEP = new String(new char[] { 0 });
	private static final String XMLNS = "urn:ietf:params:xml:ns:xmpp-sasl";

	private final XmppConnection connection;
	private final DecoderRegistry decoders;
	private final EmiteEventBus eventBus;
	private Credentials currentCredentials;
	private Mechanism currentMechanism;

	@Inject
	public SASLManager(final XmppConnection connection, final DecoderRegistry decoders) {
		this.connection = connection;
		eventBus = connection.getEventBus();
		this.decoders = decoders;

		connection.addStanzaReceivedHandler(new StanzaHandler() {
			@Override
			public void onStanza(final StanzaEvent event) {
				final IPacket stanza = event.getStanza();
				final String name = stanza.getName();
				if (!XMLNS.equals(stanza.getAttribute("xmlns"))) {
					return;
				}
				if ("challenge".equals(name)) {
					sendAuthorizationResponse(stanza);
				} else if ("failure".equals(name)) {
					eventBus.fireEvent(new AuthorizationResultEvent());
					currentCredentials = null;
					currentMechanism = null;
				} else if ("success".equals(name)) {
					handleSuccess(stanza);
				}
			}
		});
	}

	/**
	 * Add a handler to know when an authorization transaction has a result
	 * 
	 * @param handler
	 */
	public void addAuthorizationResultHandler(final AuthorizationResultHandler handler) {
		AuthorizationResultEvent.bind(eventBus, handler);
	}

	public void sendAuthorizationRequest(final Credentials credentials, IPacket mech_feature) {
		currentCredentials = credentials;
		final List<? extends IPacket> mechs = mech_feature.getChildren(MatcherFactory.byName("mechanism"));
		final IPacket response = credentials.isAnoymous() ? createAnonymousAuthorization() : createAuthorization(credentials, mechs);
		connection.send(response);
	}
	
	public void handleSuccess(final IPacket stanza) {
		// take(drugs); // This turned out to be ineffective.
		// buyPetMonkey(); // Don't do this, either.
		final byte[] additionalData = decodeSASL(stanza.getText());
		if (currentMechanism.success(additionalData)) {
			eventBus.fireEvent(new AuthorizationResultEvent(currentCredentials));
			currentCredentials = null;
		} else {
			throw new MutualAuthFailure("Post-success SASL validation failed.");
		}
	}
	
	public void sendAuthorizationResponse(final IPacket stanza) {
		final byte[] challenge = decodeSASL(stanza.getText());
		final IPacket response = new Packet("response", XMLNS);
		response.setText(encodeSASL(currentMechanism.nextResponse(challenge)));
		connection.send(response);
	}
	
	private static final byte[] decodeSASL(final String input) {
		if (input == null) {
			return null;
		}
		if (input.equals("=")) {
			return new byte[0];
		} else {
			return Base64Coder.decode(input.toCharArray());
		}
	}
	
	private static final String encodeSASL(final byte[] output) {
		if (output == null) {
			return null;
		}
		if (output.length == 0) {
			return "=";
		}
		return new String(Base64Coder.encode(output));
	}

	private IPacket createAnonymousAuthorization() {
		final IPacket auth = new Packet("auth", XMLNS).With("mechanism", "ANONYMOUS");
		return auth;
	}

	class Plain implements Mechanism {
		final Credentials credentials;
		final DecoderRegistry decoders;
		public Plain(final Credentials creds, final DecoderRegistry decoders) {
			this.credentials = creds;
			this.decoders = decoders;
		}
		public final byte[] initialResponse() {
			final String userName = credentials.getXmppUri().getNode();
			final PasswordDecoder decoder = decoders.getDecoder(credentials.getEncodingMethod());

			if (decoder == null)
				throw new RuntimeException("No password decoder found to convert from " + credentials.getEncodingMethod() + "to " + Credentials.ENCODING_BASE64);

			final String password = decoder.decode(credentials.getEncodingMethod(), credentials.getEncodedPassword());
			final String auth = userName + "@" + credentials.getXmppUri().getHost() + SEP + userName + SEP + password;
			return auth.getBytes();
		}
		public final byte[] nextResponse(final byte[] resp) {
			if (resp != null) {
				throw new UnexpectedChallenge("Server gave a challenge to PLAIN: " + resp);
			}
			return this.initialResponse();
		}
		public boolean success(final byte[] anything) {
			if (anything != null) {
				throw new UnexpectedChallenge("Server gave additional data with success to PLAIN: " + anything);
			}
			return true;
		}
		public final String getName() {
			return "PLAIN";
		}
	}
	
	private IPacket createAuthorization(final Credentials credentials, final List<? extends IPacket> mech_elements) {
		final List<String> mechs = new ArrayList<String>();
		for (IPacket mech_el : mech_elements) {
			String mech_name = mech_el.getText();
			if (mech_name == null) continue;
			mechs.add(mech_name.toUpperCase());
		}
		if (mechs.contains("SCRAM-SHA-1")) {
			this.currentMechanism = new ScramSHA1Client(credentials, decoders);
		} else if (mechs.contains("PLAIN")) {
			this.currentMechanism = new SASLManager.Plain(credentials, decoders);
		}
		if (this.currentMechanism == null) {
			throw new NoMechanisms("No available mechanisms for authentication");
		}
		final IPacket auth = new Packet("auth", XMLNS).With("mechanism", currentMechanism.getName());
		auth.setText(encodeSASL(currentMechanism.initialResponse()));
		return auth;
	}

}
