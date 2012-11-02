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

package com.calclab.emite.core.client.bosh;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import com.calclab.emite.core.client.conn.ConnectionSettings;
import com.calclab.emite.core.client.events.EmiteEventBus;
import com.calclab.emite.core.client.packet.Packet;
import com.calclab.emite.xtesting.EmiteTestsEventBus;
import com.calclab.emite.xtesting.ServicesTester;
import com.calclab.emite.xtesting.ServicesTester.Request;
import com.calclab.emite.xtesting.matchers.IsPacketLike;

public class XmppBoshConnectionTests {

	private final ServicesTester services;
	private final XmppBoshConnection connection;

	public XmppBoshConnectionTests() {
		services = new ServicesTester();
		final EmiteEventBus eventBus = EmiteTestsEventBus.create("et");
		connection = new XmppBoshConnection(eventBus, services);
	}

	@Test
	public void shouldSendInitialBody() {
		connection.setSettings(new ConnectionSettings("httpBase", "localhost"));
		connection.connect();
		assertEquals(1, services.requestSentCount());
		final IsPacketLike matcher = IsPacketLike.build("<body to='localhost' " + "content='text/xml; charset=utf-8' xmlns:xmpp='urn:xmpp:xbosh' "
				+ " ack='1' hold='1' secure='true' xml:lang='en' " + "xmpp:version='1.0' wait='60' xmlns='http://jabber.org/protocol/httpbind' />");
		assertTrue(matcher.matches(services.getSentPacket(0), System.out));
	}
	
	@Test
	public void testConnectionTimeout() {
		connection.setSettings(new ConnectionSettings("httpBase", "localhost", "1.6", 30, 50, 2));
		connection.connect();
		Request request = services.getLastRequest();
		request.listener.onResponseReceived(200, "<body sid='sid' wait='30' inactivity='50' maxpause='300' />", request.request);
		
		connection.send(new Packet("test"));
		request = services.getLastRequest();
		int expectedTimeout = 55000; // 30s + (50s / 2)
		assertEquals("Incorrect connection timeout", expectedTimeout, request.timeoutMillis);
	}
}
