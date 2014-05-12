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

import static com.calclab.emite.core.client.xmpp.stanzas.XmppURI.uri;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.junit.Before;
import org.junit.Test;

import com.calclab.emite.core.client.packet.IPacket;
import com.calclab.emite.core.client.packet.Packet;
import com.calclab.emite.core.client.xmpp.session.Credentials;
import com.calclab.emite.core.client.xmpp.stanzas.XmppURI;
import com.calclab.emite.xtesting.XmppConnectionTester;

public class SASLManagerTest {
	private SASLManager manager;
	private XmppConnectionTester connection;
	protected AuthorizationResultEvent authEvent;
	private IPacket mechanisms_with_plain;
	private IPacket mechanisms_with_anonymous;
	private IPacket mechanisms_with_unknown;
	private IPacket mechanisms_empty;

	@Before
	public void beforeTests() {
		connection = new XmppConnectionTester();
		manager = new SASLManager(connection, new DecoderRegistry());
		authEvent = null;
		AuthorizationResultEvent.bind(connection.getEventBus(), new AuthorizationResultHandler() {
			@Override
			public void onAuthorization(final AuthorizationResultEvent event) {
				authEvent = event;
			}
		});
		mechanisms_with_plain = new Packet("mechanisms", "urn:ietf:params:xml:ns:xmpp-sasl");
		IPacket tmp = new Packet("mechanism");
		mechanisms_with_plain.addChild(tmp);
		tmp.setText("UNKNOWN");
		tmp = new Packet("mechanism");
		tmp.setText("PLAIN");
		mechanisms_with_plain.addChild(tmp);
		mechanisms_with_anonymous = new Packet("mechanisms", "urn:ietf:params:xml:ns:xmpp-sasl");
		tmp = new Packet("mechanism");
		tmp.setText("ANONYMOUS");
		mechanisms_with_anonymous.addChild(tmp);
		tmp = new Packet("mechanism");
		tmp.setText("PLAIN");
		mechanisms_with_anonymous.addChild(tmp);
		mechanisms_with_unknown = new Packet("mechanisms", "urn:ietf:params:xml:ns:xmpp-sasl");
		tmp = new Packet("mechanism");
		tmp.setText("UNKNOWN");
		mechanisms_with_unknown.addChild(tmp);
		tmp = new Packet("mechanism");
		tmp.setText("FOOBAR");
		mechanisms_with_unknown.addChild(tmp);
		mechanisms_empty = new Packet("mechanisms", "urn:ietf:params:xml:ns:xmpp-sasl");
	}

	@Test
	public void shouldHandleSuccessWhenAuthorizationSent() {
		manager.sendAuthorizationRequest(credentials(uri("me@domain"), "password"), mechanisms_with_plain);
		connection.receives("<success xmlns=\"urn:ietf:params:xml:ns:xmpp-sasl\"/>");
		assertNotNull(authEvent);
		assertTrue(authEvent.isSucceed());
	}

	@Test
	public void shouldHandleFailure() {
		manager.sendAuthorizationRequest(credentials(uri("node@domain"), "password"), mechanisms_with_plain);
		connection.receives("<failure xmlns=\"urn:ietf:params:xml:ns:xmpp-sasl\"><not-authorized/></failure>");
		assertNotNull(authEvent);
		assertFalse(authEvent.isSucceed());
	}

	@Test
	public void shouldSendAnonymousIfAnonymousProvided() {
		manager.sendAuthorizationRequest(credentials(Credentials.ANONYMOUS, null), mechanisms_with_anonymous);
		final IPacket packet = new Packet("auth", "urn:ietf:params:xml:ns:xmpp-sasl").With("mechanism", "ANONYMOUS");
		assertTrue(connection.hasSent(packet));
	}

	@Test
	public void shouldSendPlainAuthorizationUnlessAnonymous() {
		manager.sendAuthorizationRequest(credentials(uri("node@domain/resource"), "password"), mechanisms_with_plain);
		final IPacket packet = new Packet("auth", "urn:ietf:params:xml:ns:xmpp-sasl").With("mechanism", "PLAIN");
		assertTrue(connection.hasSent(packet));
	}

	@Test
	public void shouldSendPlainAuthorizationWithoutNode() {
		manager.sendAuthorizationRequest(credentials(uri("domain/resource"), ""), mechanisms_with_plain);
		final IPacket packet = new Packet("auth", "urn:ietf:params:xml:ns:xmpp-sasl").With("mechanism", "PLAIN");
		assertTrue(connection.hasSent(packet));
	}

	private Credentials credentials(final XmppURI uri, final String password) {
		final Credentials credentials = new Credentials(uri, password, Credentials.ENCODING_NONE);
		return credentials;
	}
}
