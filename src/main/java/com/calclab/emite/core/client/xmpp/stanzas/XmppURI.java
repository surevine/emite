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

package com.calclab.emite.core.client.xmpp.stanzas;

import com.calclab.emite.base.stringprep.Stringprep;
import com.calclab.emite.base.stringprep.StringprepException;

/**
 * Defines a XMPP URI.
 * 
 * http://www.xmpp.org/drafts/attic/draft-saintandre-xmpp-uri-00.html
 * 
 * <code>XMPP- = ["xmpp:"] node "@" host[ "/" resource]</code>
 * 
 */
public class XmppURI implements HasJID {
	private static final XmppURIFactory factory = new XmppURIFactory();

	/**
	 * Parse the string and return a JID (a uri without resource)
	 * 
	 * @param jid
	 *            the string to be parsed
	 * @return a XmppURI object if the jid is a valid JID string, null otherwise
	 */
	public static XmppURI jid(final String jid) {
		return uri(jid).getJID();
	}

	/**
	 * Parse a string and return a complete XmppURI object
	 * 
	 * @param xmppUri
	 *            the string to be parsed
	 * @return a XmppURI object if the string is a valid XmppURI string, null
	 *         otherwise
	 * 
	 */
	public static XmppURI uri(final String xmppUri) {
		return factory.parse(xmppUri);
	}

	/**
	 * Create a new XmppURI object with the given attributes
	 * 
	 * @param node
	 *            the node of the uri
	 * @param host
	 *            the host of the uri
	 * @param resource
	 *            the resource of the uri
	 * @return a XmppURI object, never null
	 * @throws StringprepException 
	 * @throws NullPointerException 
	 */

	public static XmppURI uri(final String node, final String host, final String resource) throws NullPointerException, StringprepException {
		final XmppURI xmppURI = new XmppURI(node, host, resource);
		factory.cache(xmppURI);
		return xmppURI;
	}
	/**
	 * As uri(), but may return null if the arguments are invalid.
	 * 
	 * @param node
	 * @param host
	 * @param resource
	 * @return XmppURI or null
	 */
	public static XmppURI uri_or_null(final String node, final String host, final String resource) {
		try {
			return uri(node, host, resource);
		} catch (Exception e) {
			return null;
		}
	}

	private final String host;
	private final String node;
	private final String representation;
	private final String resource;

	/**
	 * 
	 * @param jid
	 * @param resource
	 *            <code> resource      = *( unreserved / escaped )
                reserved      = ";" / "/" / "?" / ":" / "@" / "&" / "=" / "+" /
                "$" / "," / "[" / "]" </code>
	 * @throws StringprepException 
	 * @throws NullPointerException 
	 * 
	 */
	private XmppURI(final String node, final String host, final String resource) throws NullPointerException, StringprepException {
		assert host != null : "Host can't be null";
		this.node = node != null ? Stringprep.nodeprep(node) : null;
		this.host = Stringprep.nameprep(host);
		this.resource = resource != null ? Stringprep.resourceprep(resource) : null;
		this.representation = (this.node != null ? this.node + "@" : "") + this.host + (this.resource != null ? "/" + this.resource : "");
	}

	@Override
	public boolean equals(final Object obj) {
		if (obj == null)
			return false;
		if (obj == this)
			return true;
		return representation.equals(((XmppURI) obj).representation);
	}

	public boolean equalsNoResource(final XmppURI other) {
		if (other == null)
			return false;
		if (this == other)
			return true;
		if (node == null && other.node != null)
			return false;
		return host.equals(other.host) && (node == null || node.equals(other.node));
	}

	/**
	 * @return the uri's host
	 */
	public String getHost() {
		return host;
	}

	/**
	 * @return a new XmppURI object with the same host as this one
	 */
	public XmppURI getHostURI() {
		return uri_or_null(null, host, null);
	}

	/**
	 * Returns the JID of this URI (a XmppURI without resource)
	 * 
	 * @return the JID of this URI
	 */
	@Override
	public XmppURI getJID() {
		return uri_or_null(node, host, null);
	}

	/**
	 * @return uri's node
	 */
	public String getNode() {
		return node;
	}

	/**
	 * @return uri's resource
	 */
	public String getResource() {
		return resource;
	}

	/**
	 * Return the node or the host if node is null
	 * 
	 * @return an never null short name representation
	 */
	public String getShortName() {
		return node == null ? host : node;
	}

	@Override
	public int hashCode() {
		return representation.hashCode();
	}

	/**
	 * @return true if this uri has node, false otherwise
	 */
	public boolean hasNode() {
		return node != null;
	}

	/**
	 * @return true if this uri has resource, false otherwise
	 */
	public boolean hasResource() {
		return resource != null;
	}

	@Override
	public String toString() {
		return representation;
	}
}
