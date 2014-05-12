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
		String initialResponse();
		String nextResponse(String challenge);
		boolean success(String additionalData);
		String getName();
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
		final String additionalData = decodeSASL(stanza.getText());
		if (currentMechanism.success(additionalData)) {
			eventBus.fireEvent(new AuthorizationResultEvent(currentCredentials));
			currentCredentials = null;
		} else {
			throw new RuntimeException("Post-success SASL validation failed.");
		}
	}
	
	public void sendAuthorizationResponse(final IPacket stanza) {
		
	}
	
	private static final String decodeSASL(final String input) {
		String challenge = null;
		if (input == null) {
			return null;
		}
		if (input.equals("=")) {
			challenge = "";
		} else {
			challenge = Base64Coder.decodeString(input);
		}
		return challenge;
	}
	
	private static final String encodeSASL(final String output) {
		if (output == null) {
			return null;
		}
		if (output.equals("")) {
			return "=";
		}
		return Base64Coder.encodeString(output);
	}

	private IPacket createAnonymousAuthorization() {
		final IPacket auth = new Packet("auth", XMLNS).With("mechanism", "ANONYMOUS");
		return auth;
	}

	class Plain implements Mechanism {
		Credentials credentials;
		public Plain(final Credentials creds) {
			this.credentials = creds;
		}
		public final String initialResponse() {
			final String userName = credentials.getXmppUri().getNode();
			final PasswordDecoder decoder = decoders.getDecoder(credentials.getEncodingMethod());

			if (decoder == null)
				throw new RuntimeException("No password decoder found to convert from " + credentials.getEncodingMethod() + "to " + Credentials.ENCODING_BASE64);

			final String password = decoder.decode(credentials.getEncodingMethod(), credentials.getEncodedPassword());
			final String auth = userName + "@" + credentials.getXmppUri().getHost() + SEP + userName + SEP + password;
			return auth;
		}
		public final String nextResponse(final String resp) {
			if (resp != null) {
				throw new RuntimeException("Server gave a challenge to PLAIN: " + resp);
			}
			return this.initialResponse();
		}
		public boolean success(final String anything) {
			if (anything != null) {
				throw new RuntimeException("Server gave additional data with success to PLAIN: " + anything);
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
			mechs.add(mech_el.getText().toUpperCase());
		}
		if (mechs.contains("PLAIN")) {
			this.currentMechanism = new SASLManager.Plain(credentials);
		}
		if (this.currentMechanism == null) {
			throw new RuntimeException("No available mechanisms for authentication");
		}
		final IPacket auth = new Packet("auth", XMLNS).With("mechanism", currentMechanism.getName());
		auth.setText(encodeSASL(currentMechanism.initialResponse()));
		return auth;
	}

}
