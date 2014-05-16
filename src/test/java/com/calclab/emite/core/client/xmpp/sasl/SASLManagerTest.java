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
	private IPacket mechanisms_with_scram;
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
		mechanisms_with_scram = new Packet("mechanisms", "urn:ietf:params:xml:ns:xmpp-sasl");
		tmp = new Packet("mechanism");
		mechanisms_with_scram.addChild(tmp);
		tmp.setText("UNKNOWN");
		tmp = new Packet("mechanism");
		tmp.setText("PLAIN");
		mechanisms_with_scram.addChild(tmp);
		tmp.setText("SCRAM-SHA-1");
		mechanisms_with_scram.addChild(tmp);
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
	
	@Test(expected = RuntimeException.class) // Actually, this throws an UnexpectedChallenge exception, but GWT hides that.
	public void shouldRejectSuccessWhenAuthorizationSentWithData() {
		manager.sendAuthorizationRequest(credentials(uri("me@domain"), "password"), mechanisms_with_plain);
		connection.receives("<success xmlns=\"urn:ietf:params:xml:ns:xmpp-sasl\">1234</success>");
		assert(authEvent == null);
		assertFalse(authEvent.isSucceed());
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
	public void shouldSendPlainAuthorizationIfOnlyPlain() {
		manager.sendAuthorizationRequest(credentials(uri("node@domain/resource"), "password"), mechanisms_with_plain);
		final IPacket packet = new Packet("auth", "urn:ietf:params:xml:ns:xmpp-sasl").With("mechanism", "PLAIN");
		assertTrue(connection.hasSent(packet));
	}

	@Test
	public void shouldSendScramAuthorizationIfAvailable() {
		manager.sendAuthorizationRequest(credentials(uri("node@domain/resource"), "password"), mechanisms_with_scram);
		final IPacket packet = new Packet("auth", "urn:ietf:params:xml:ns:xmpp-sasl").With("mechanism", "SCRAM-SHA-1");
		assertTrue(connection.hasSent(packet));
	}

	@Test
	public void shouldHandleChallenge() {
		manager.sendAuthorizationRequest(credentials(uri("node@domain/resource"), "password"), mechanisms_with_plain);
		final IPacket packet = new Packet("auth", "urn:ietf:params:xml:ns:xmpp-sasl").With("mechanism", "PLAIN");
		assertTrue(connection.hasSent(packet));
		connection.receives("<challenge xmlns=\"urn:ietf:params:xml:ns:xmpp-sasl\"/>");
		final IPacket packet2 = new Packet("response", "urn:ietf:params:xml:ns:xmpp-sasl");
		assertTrue(connection.hasSent(packet2));
	}

	@Test(expected = SASLManager.NoMechanisms.class)
	public void shouldFailIfPlainMissing() {
		manager.sendAuthorizationRequest(credentials(uri("node@domain/resource"), "password"), mechanisms_with_unknown);
		final IPacket packet = new Packet("auth", "urn:ietf:params:xml:ns:xmpp-sasl").With("mechanism", "PLAIN");
		assertFalse(connection.hasSent(packet));
	}

	@Test(expected = SASLManager.NoMechanisms.class)
	public void shouldFailIfNoMechanisms() {
		manager.sendAuthorizationRequest(credentials(uri("node@domain/resource"), "password"), mechanisms_empty);
		final IPacket packet = new Packet("auth", "urn:ietf:params:xml:ns:xmpp-sasl").With("mechanism", "PLAIN");
		assertFalse(connection.hasSent(packet));
	}

	@Test
	public void shouldSendPlainAuthorizationWithoutNode() {
		manager.sendAuthorizationRequest(credentials(uri("domain/resource"), ""), mechanisms_with_plain);
		final IPacket packet = new Packet("auth", "urn:ietf:params:xml:ns:xmpp-sasl").With("mechanism", "PLAIN");
		assertTrue(connection.hasSent(packet));
	}

	@Test
	public void scramXorTest() {
		byte[] one = new byte[4];
		for (int i=0; i!=4; ++i) {
			one[i] = (byte) 0xFF;
		}
		byte[] two = new byte[4];
		two[0] = 0x00;
		two[1] = 0x0F;
		two[2] = (byte)0xF0;
		two[3] = (byte)0xFF;
		byte[] three = CryptoUtils.XOR(one, two);
		assertTrue(three[0] == (byte)0xFF);
		assertTrue(three[1] == (byte)0xF0);
		assertTrue(three[2] == (byte)0x0F);
		assertTrue(three[3] == (byte)0x00);
	}
	
	@Test
	public void scramExampleTest() {
		ScramSHA1Client mech = new ScramSHA1Client(credentials(uri("user@domain"), "pencil"), new DecoderRegistry());
		mech.forceCnonce("fyko+d2lbbFgONRv9qkxdawL");
		assertTrue(new String(mech.initialResponse()).equals("n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL"));
		String clientFinal = new String(mech.nextResponse("r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096".getBytes()));
		assertTrue(clientFinal.equals("c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts="));
		assertTrue(mech.success("v=rmF9pqV8S7suAoZWja4dJRkFsKQ=".getBytes()));
	}

	private Credentials credentials(final XmppURI uri, final String password) {
		final Credentials credentials = new Credentials(uri, password, Credentials.ENCODING_NONE);
		return credentials;
	}
}
