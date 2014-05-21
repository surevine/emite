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

package com.calclab.emite.core.client.services;

import com.calclab.emite.core.client.packet.IPacket;

public interface Services {
	public static final int DEFAULT_TIMEOUT_MILLIS = 300000;
	
	long getCurrentTime();

	void schedule(int msecs, ScheduledAction action);

	/**
	 * Sends an http request.
	 * <p>Note: the default timeout is 5 minutes
	 * @param httpBase
	 * @param request
	 * @param listener
	 * @throws ConnectorException
	 */
	void send(String httpBase, String request, ConnectorCallback listener) throws ConnectorException;

	/**
	 * Sends an HTTP request.
	 * @param httpBase
	 * @param request
	 * @param listener
	 * @param timeoutMillis
	 * @throws ConnectorException
	 */
	void send(String httpBase, String request, ConnectorCallback listener, int timeoutMillis) throws ConnectorException;

	String toString(IPacket iPacket);

	/**
	 * Convert xml to IPacket
	 * 
	 * @param xml
	 *            text
	 * @return IPacket or NoPacket.INSTANCE if problems
	 */
	IPacket toXML(String xml);

}
