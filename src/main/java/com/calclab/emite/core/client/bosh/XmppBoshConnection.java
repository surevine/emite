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

import java.util.HashSet;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.calclab.emite.core.client.conn.ConnectionSettings;
import com.calclab.emite.core.client.conn.StanzaSentEvent;
import com.calclab.emite.core.client.conn.XmppConnection;
import com.calclab.emite.core.client.conn.XmppConnectionBoilerPlate;
import com.calclab.emite.core.client.events.EmiteEventBus;
import com.calclab.emite.core.client.packet.IPacket;
import com.calclab.emite.core.client.packet.Packet;
import com.calclab.emite.core.client.services.ConnectorCallback;
import com.calclab.emite.core.client.services.ScheduledAction;
import com.calclab.emite.core.client.services.Services;
import com.google.gwt.core.client.GWT;
import com.google.inject.Inject;
import com.google.inject.Singleton;

/**
 * A Bosh connection implementation.
 * 
 * @see XmppConnection
 */
@Singleton
public class XmppBoshConnection extends XmppConnectionBoilerPlate {
	
	/** 
	 * Simple service to call {@link XmppBoshConnection#continueConnection()} once every so often as the connector
	 * occasionally seems to be able to get into a state where there are no open connections (and if there are no
	 * connections then there are no responses to trigger more connections and the client just hangs)
	 */
	class Heartbeat implements ScheduledAction {
		private final XmppBoshConnection connection;
		private final int checkMillis;
		
		/**
		 * @param connection the BOSH connector
		 * @param checkMillis the number of milliseconds to keep checking for open connections
		 */
		Heartbeat(XmppBoshConnection connection, int checkMillis) {
			this.connection = connection;
			this.checkMillis = checkMillis;
			run();
		}
		
		@Override
		public void run() {
			try {
				// If the connection has errors then the normal retry code will be periodically trying the connection
				if(connection.isActive() && !connection.hasErrors()) {
					// We can safely call this as continueConnection() won't do anything if it doesn't need to
					connection.continueConnection();
				}
			} finally {
				connection.services.schedule(this.checkMillis, this);
			}
		}
	}
	
	/**
	 * How many milliseconds between retries when a potentially recoverable error is detected
	 */
	private static final int ERROR_RETRY_PERIOD_MILLIS = 2000;
	
	/**
	 * How many seconds to timeout the connection retry on an error if we don't have an
	 * inactivity period defined (e.g. on initial connection attempt)
	 */
	private static final int ERROR_RETRY_TIMEOUT_SECONDS = 60;
	
	/**
	 * How many seconds to add to the inactivity period for the connection timeout. Essentially
	 * if we haven't had a reply from the server after inactivity + this value then the connection
	 * will time out.
	 */
	private static final int DEFAULT_CONNECTION_TIMEOUT_MILLIS = 120000; // 2 minutes
	
	/**
	 * How many milliseconds between calls to continueConnection.<br />
	 * Set to zero to disable
	 * 
	 * @see Heartbeat
	 */
	private static final int HEARTBEAT_PERIOD_MILLIS = 5000;
	
	private static final Logger logger = Logger.getLogger(XmppBoshConnection.class.getName());
	
	private int activeConnections;
	private final Services services;
	private final ConnectorCallback listener;
	private boolean shouldCollectResponses;
	
	/**
	 * Maintains a set of requests which encountered errors and are currently being
	 * retried. The class should not send any new requests if this set is non-empty
	 */
	private final HashSet<String> erroredRequests;
	
	@Inject
	public XmppBoshConnection(final EmiteEventBus eventBus, final Services services) {
		super(eventBus);
		this.services = services;
		
		erroredRequests = new HashSet<String>();

		if(HEARTBEAT_PERIOD_MILLIS > 0) {
			new Heartbeat(this, HEARTBEAT_PERIOD_MILLIS);
		}
		
		listener = new ConnectorCallback() {

			@Override
			public void onError(final String request, final Throwable throwable) {
				if (isActive()) {
					final int e = incrementErrors();
					logger.log(Level.WARNING, "Connection error #" + e, throwable);
					
					erroredRequests.add(request);
					
					final String sid = getStreamSettings().sid;
					
					/* 
					 * TODO If there are multiple retrying connections at once then the error count will be
					 * artificially increased so we should handle that properly.
					 */
					// If we've been errored for longer than the "inactivity" time then there is no
					// way we can get the session back, so we may as well just give up!
					if((e * ERROR_RETRY_PERIOD_MILLIS / 1000) > getErrorTimeoutMillis()) {
						--activeConnections;
						logger.severe("Connection errored for longer than inactivity timeout ("
								+ getStreamSettings().getInactivity() + "s) - Notifying connection error");
						fireError("Connection error: " + throwable.toString());
						disconnect();
					} else {;
						logger.fine("Retrying connection...");
						fireRetry(e, ERROR_RETRY_PERIOD_MILLIS);
						services.schedule(ERROR_RETRY_PERIOD_MILLIS, new ScheduledAction() {
							@Override
							public void run() {
								// If the session hasn't been changed in the meantime...
								if((getStreamSettings().sid == null) || getStreamSettings().sid.equals(sid)) {
									logger.info("Error retry: " + e);
									--activeConnections;
									send(request);
								}
							}
						});
						logger.fine("Retry queued for " + ERROR_RETRY_PERIOD_MILLIS + "ms");
					}
				}
			}

			@Override
			public void onResponseReceived(final int statusCode, final String content, final String originalRequest) {
				if (isActive()) {
					// tests
					if (statusCode == 404) {
						// We will get a 404 if the session has timed out - not much we can do here unfortunately
						activeConnections--;
						fireError("404 Connection Error (session removed ?!) : " + content);
						disconnect();
					} else if (statusCode != 200 && statusCode != 0) {
						onError(originalRequest, new Exception("Bad status: " + statusCode + " " + content));
					} else {
						final IPacket response = services.toXML(content);
						if (response != null && "body".equals(response.getName())) {
							activeConnections--;
//							clearErrors();
							/* 
							 * We could just call remove directly here, but by doing a separate contains check
							 * we can log the fact that an error has recovered, and still will only be checking
							 * the set once in the 99% no error situation
							 */
							if(erroredRequests.contains(originalRequest)) {
								logger.finer("Successfully resent errored connection on session " + getStreamSettings().sid);
								erroredRequests.remove(originalRequest);
							}
							fireResponse(content);
							handleResponse(response);
						} else {
							onError(originalRequest, new Exception("Bad response: " + statusCode + " " + content));
						}
					}
				}
			}
		};
	}
	
	@Override
	public void connect() {
		assert getConnectionSettings() != null : "You should set user settings before connect!";
		clearErrors();

		if (!isActive()) {
			setActive(true);
			setStream(new StreamSettings());
			activeConnections = 0;
			createInitialBody(getConnectionSettings());
			sendBody();
		}
	}

	@Override
	public void disconnect() {
		logger.finer("BoshConnection - Disconnected called - Clearing current body and send a priority 'terminate' stanza.");
		// Clearing all queued stanzas
		setCurrentBody(null);
		// Create a new terminate stanza and force the send
		createBodyIfNeeded();
		getCurrentBody().setAttribute("type", "terminate");
		sendBody(true);
		setActive(false);
		getStreamSettings().sid = null;
		fireDisconnected("logged out");
	}

	@Override
	public boolean isConnected() {
		return getStreamSettings() != null;
	}

	@Override
	public StreamSettings pause() {
		if (getStreamSettings() != null && getStreamSettings().sid != null) {
			createBodyIfNeeded();
			getCurrentBody().setAttribute("pause", getStreamSettings().getMaxPauseString());
			sendBody(true);
			return getStreamSettings();
		}
		return null;
	}

	@Override
	public void restartStream() {
		createBodyIfNeeded();
		getCurrentBody().setAttribute("xmlns:xmpp", "urn:xmpp:xbosh");
		getCurrentBody().setAttribute("xmpp:restart", "true");
		getCurrentBody().setAttribute("to", getConnectionSettings().hostName);
		getCurrentBody().setAttribute("xml:lang", "en");
	}

	@Override
	public boolean resume(final StreamSettings settings) {
		setActive(true);
		setStream(settings);
		continueConnection();
		return isActive();
	}

	@Override
	public void send(final IPacket packet) {
		createBodyIfNeeded();
		getCurrentBody().addChild(packet);
		sendBody();
		eventBus.fireEvent(new StanzaSentEvent(packet));
	}

	@Override
	public String toString() {
		return "Bosh in " + (isActive() ? "active" : "inactive") + " stream=" + getStreamSettings();
	}

	/**
	 * After receiving a response from the connection manager, if none of the
	 * client's requests are still being held by the connection manager (and if
	 * the session is not a Polling Session), the client SHOULD make a new
	 * request as soon as possible. In any case, if no requests are being held,
	 * the client MUST make a new request before the maximum inactivity period
	 * has expired. The length of this period (in seconds) is specified by the
	 * 'inactivity' attribute in the session creation response.
	 * 
	 * @see http://xmpp.org/extensions/xep-0124.html#inactive
	 * @param ack
	 */
	private void continueConnection() {
		if (isConnected() && activeConnections == 0) {
			if (getCurrentBody() != null) {
				sendBody();
			} else {
				final long currentRID = getStreamSettings().rid;
				final int waitTime = 300;
				services.schedule(waitTime, new ScheduledAction() {
					@Override
					public void run() {
						if (getCurrentBody() == null && getStreamSettings().rid == currentRID && activeConnections == 0 && !hasErrors()) {
							createBodyIfNeeded();
							// Whitespace keep-alive
							// getCurrentBody().setText(" ");
							sendBody();
						}
					}
				});
			}
		}
	}

	private void createBodyIfNeeded() {
		if (getCurrentBody() == null) {
			final Packet body = new Packet("body");
			body.With("xmlns", "http://jabber.org/protocol/httpbind");
			body.With("rid", getStreamSettings().getNextRid());
			if (getStreamSettings() != null) {
				body.With("sid", getStreamSettings().sid);
			}
			setCurrentBody(body);
		}
	}

	private void createInitialBody(final ConnectionSettings userSettings) {
		final Packet body = new Packet("body");
		body.setAttribute("content", "text/xml; charset=utf-8");
		body.setAttribute("xmlns", "http://jabber.org/protocol/httpbind");
		body.setAttribute("xmlns:xmpp", "urn:xmpp:xbosh");
		body.setAttribute("ver", userSettings.version);
		body.setAttribute("xmpp:version", "1.0");
		body.setAttribute("xml:lang", "en");
		body.setAttribute("ack", "1");
		body.setAttribute("secure", Boolean.toString(userSettings.secure));
		body.setAttribute("rid", getStreamSettings().getNextRid());
		body.setAttribute("to", userSettings.hostName);
		if (userSettings.routeHost != null && userSettings.routePort != null) {
			String routeHost = userSettings.routeHost;
			if (routeHost == null) {
				routeHost = userSettings.hostName;
			}
			Integer routePort = userSettings.routePort;
			if (routePort == null) {
				routePort = 5222;
			}
			body.setAttribute("route", "xmpp:" + routeHost + ":" + routePort);
		}
		body.With("hold", userSettings.hold);
		body.With("wait", userSettings.wait);
		setCurrentBody(body);
	}

	private void handleResponse(final IPacket response) {
		if (isTerminate(response.getAttribute("type"))) {
			getStreamSettings().sid = null;
			setActive(false);
			fireDisconnected("disconnected by server");
		} else {
			try {
				if (getStreamSettings().sid == null) {
					initStream(response);
					fireConnected();
				}
				shouldCollectResponses = true;
				final List<? extends IPacket> stanzas = response.getChildren();
				for (final IPacket stanza : stanzas) {
					try {
						fireStanzaReceived(stanza);
					} catch(Exception e) {
						logger.log(Level.WARNING, "Error occurred while processing received stanza: " + stanza.toString(), e);
					}
				}
			} finally {
				shouldCollectResponses = false;
				continueConnection();
			}
		}
	}

	private void initStream(final IPacket response) {
		final StreamSettings stream = getStreamSettings();
		stream.sid = response.getAttribute("sid");
		stream.setWait(response.getAttribute("wait"));
		stream.setInactivity(response.getAttribute("inactivity"));
		stream.setMaxPause(response.getAttribute("maxpause"));
	}

	private boolean isTerminate(final String type) {
		// Openfire bug: terminal instead of terminate
		return "terminate".equals(type) || "terminal".equals(type);
	}

	/**
	 * Sends a new request (and count the activeConnections)
	 * 
	 * @param request
	 */
	private void send(final String request) {
		try {
			activeConnections++;
			
			GWT.log("Timeout: " + getConnectionTimeoutMillis());
			
			services.send(getConnectionSettings().httpBase, request, listener, getConnectionTimeoutMillis());
		} catch (final Exception e) {
			activeConnections--;
			logger.log(Level.SEVERE, "Exception occurred on send", e);
		}
		getStreamSettings().lastRequestTime = services.getCurrentTime();
	}

	private void sendBody() {
		sendBody(false);
	}

	private void sendBody(final boolean force) {
		// TODO: better semantics
		if (force || !shouldCollectResponses && isActive() && activeConnections < getConnectionSettings().maxRequests && !hasErrors()) {
			final String request = services.toString(getCurrentBody());
			setCurrentBody(null);
			send(request);
		} else {
			logger.finer("Send body simply queued");
		}
	}
	
	@Override
	public boolean hasErrors() {
		return !erroredRequests.isEmpty();
	}

	@Override
	public void clearErrors() {
		super.clearErrors();
		
		this.erroredRequests.clear();
	}
	
	/**
	 * Returns the number of seconds after which an errored connection should be dropped. This
	 * is normally the inactivity period defined by the server, but may default to {@link #ERROR_RETRY_TIMEOUT_SECONDS}
	 * if the connection has not yet been established
	 * 
	 * @return number of seconds.
	 */
	private int getErrorTimeoutMillis() {
		if((getStreamSettings() != null) && (getStreamSettings().getWait() > 0)) {
			return getStreamSettings().getWait();
		}
		
		return ERROR_RETRY_TIMEOUT_SECONDS;
	}
	
	private int getConnectionTimeoutMillis() {
		if((getStreamSettings() != null)
				&& (getStreamSettings().getWait() > 0)
				&& (getStreamSettings().getInactivity() > 0)) {
			return ( getStreamSettings().getWait() + ( getStreamSettings().getInactivity() / 2 ) ) * 1000;
		}
		
		return DEFAULT_CONNECTION_TIMEOUT_MILLIS;
	}
}
