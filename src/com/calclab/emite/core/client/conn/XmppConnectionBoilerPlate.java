package com.calclab.emite.core.client.conn;

import com.calclab.emite.core.client.bosh.StreamSettings;
import com.calclab.emite.core.client.conn.ConnectionStateEvent.ConnectionState;
import com.calclab.emite.core.client.events.EmiteEventBus;
import com.calclab.emite.core.client.packet.IPacket;
import com.calclab.emite.core.client.packet.Packet;
import com.google.gwt.event.shared.HandlerRegistration;

/**
 * A base XmppConnection implementation with all the boiler plate code.
 * 
 * @see XmppConnection
 */
public abstract class XmppConnectionBoilerPlate implements XmppConnection {

    protected final EmiteEventBus eventBus;
    private int errors;
    private boolean active;
    private StreamSettings stream;
    private Packet currentBody;
    private ConnectionSettings connectionSettings;

    public XmppConnectionBoilerPlate(final EmiteEventBus eventBus) {
	this.eventBus = eventBus;
    }

    @Override
    public HandlerRegistration addConnectionHandler(final ConnectionStateHandler handler) {
	return eventBus.addHandler(ConnectionStateEvent.getType(), handler);
    }

    @Override
    public HandlerRegistration addConnectionResponseHandler(final ConnectionResponseHandler handler) {
	return ConnectionResponseEvent.bind(eventBus, handler);
    }

    @Override
    public HandlerRegistration addStanzaReceivedHandler(final StanzaHandler handler) {
	return StanzaReceivedEvent.bind(eventBus, handler);
    }

    @Override
    public HandlerRegistration addStanzaSentHandler(final StanzaHandler handler) {
	return StanzaSentEvent.bind(eventBus, handler);
    }

    public void clearErrors() {
	errors = 0;
    }

    protected void fireConnected() {
	eventBus.fireEvent(new ConnectionStateEvent(ConnectionState.connected));
    }

    protected void fireDisconnected(final String message) {
	eventBus.fireEvent(new ConnectionStateEvent(ConnectionState.disconnected, message));
    }

    protected void fireError(final String error) {
	eventBus.fireEvent(new ConnectionStateEvent(ConnectionState.error, error));
    }

    protected void fireResponse(final String response) {
	eventBus.fireEvent(new ConnectionResponseEvent(response));
    }

    protected void fireRetry(final Integer attempt, final Integer scedTime) {
	eventBus.fireEvent(new ConnectionStateEvent(ConnectionState.waitingForRetry,
		"The connection will try to re-connect in " + scedTime + " milliseconds.", scedTime));
    }

    protected void fireStanzaReceived(final IPacket stanza) {
	eventBus.fireEvent(new StanzaReceivedEvent(stanza));
    }

    protected void fireStanzaSent(final IPacket packet) {
	eventBus.fireEvent(new StanzaSentEvent(packet));
    }

    protected ConnectionSettings getConnectionSettings() {
	return connectionSettings;
    }

    /**
     * @return the currentBody
     */
    protected Packet getCurrentBody() {
	return currentBody;
    }

    @Override
    public EmiteEventBus getEventBus() {
	return eventBus;
    }

    /**
     * @return the stream
     */
    protected StreamSettings getStream() {
	return stream;
    }

    @Override
    public boolean hasErrors() {
	return errors != 0;
    }

    public int incrementErrors() {
	errors++;
	return errors;
    }

    /**
     * @return if the connection is active
     */
    protected boolean isActive() {
	return active;
    }

    /**
     * Set the conntection active
     * 
     * @param active
     *            true if active
     * 
     */
    protected void setActive(final boolean active) {
	this.active = active;
    }

    /**
     * @param currentBody
     *            the currentBody to set
     */
    protected void setCurrentBody(final Packet currentBody) {
	this.currentBody = currentBody;
    }

    @Override
    public void setSettings(final ConnectionSettings settings) {
	connectionSettings = settings;
    }

    /**
     * @param stream
     *            the stream to set
     */
    protected void setStream(final StreamSettings stream) {
	this.stream = stream;
    }
}