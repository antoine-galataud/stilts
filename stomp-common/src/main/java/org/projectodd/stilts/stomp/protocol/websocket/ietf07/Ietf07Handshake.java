/*
 * Copyright 2008-2011 Red Hat, Inc, and individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */

package org.projectodd.stilts.stomp.protocol.websocket.ietf07;

import java.net.URI;
import java.security.NoSuchAlgorithmException;

import org.jboss.logging.Logger;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.channel.ChannelHandler;
import org.jboss.netty.handler.codec.http.DefaultHttpRequest;
import org.jboss.netty.handler.codec.http.DefaultHttpResponse;
import org.jboss.netty.handler.codec.http.HttpHeaders;
import org.jboss.netty.handler.codec.http.HttpHeaders.Names;
import org.jboss.netty.handler.codec.http.HttpMethod;
import org.jboss.netty.handler.codec.http.HttpRequest;
import org.jboss.netty.handler.codec.http.HttpResponse;
import org.jboss.netty.handler.codec.http.HttpResponseStatus;
import org.jboss.netty.handler.codec.http.HttpVersion;
import org.projectodd.stilts.stomp.protocol.websocket.Handshake;

/**
 * Handler for ietf-00.
 *
 * @author Michael Dobozy
 * @author Bob McWhirter
 *
 */
public class Ietf07Handshake extends Handshake {

    private static Logger log = Logger.getLogger(Ietf07Handshake.class);

    public Ietf07Handshake() throws NoSuchAlgorithmException {
        this( true );
    }

    public Ietf07Handshake(boolean isClient) throws NoSuchAlgorithmException {
        super( "7" );
        this.challenge = new Ietf07WebSocketChallenge();
        this.isClient = isClient;
    }

    public boolean matches(HttpRequest request) {
        return (request.headers().contains( "Sec-WebSocket-Key" ) && getVersion().equals( request.headers().get( "Sec-WebSocket-Version" ) ));
    }

    public HttpRequest generateRequest(URI uri) throws Exception {
        HttpRequest request = new DefaultHttpRequest( HttpVersion.HTTP_1_1, HttpMethod.GET, uri.getPath() );

        request.headers().add( "Sec-WebSocket-Version", "7" );
        request.headers().add( HttpHeaders.Names.CONNECTION, "Upgrade" );
        request.headers().add( HttpHeaders.Names.UPGRADE, "WebSocket" );
        request.headers().add( HttpHeaders.Names.HOST, uri.getHost()+ ":" + uri.getPort() );
        request.headers().add( HttpHeaders.Names.SEC_WEBSOCKET_PROTOCOL, "stomp" );

        request.headers().add( "Sec-WebSocket-Key", this.challenge.getNonceBase64() );
        request.setContent( ChannelBuffers.EMPTY_BUFFER );

        return request;
    }

    @Override
    public HttpResponse generateResponse(HttpRequest request) throws Exception {
        HttpResponse response = new DefaultHttpResponse( HttpVersion.HTTP_1_1, new HttpResponseStatus( 101, "Web Socket Protocol Handshake - IETF-07" ) );

        String origin = request.headers().get( Names.ORIGIN );

        if (origin != null) {
            response.headers().add( Names.SEC_WEBSOCKET_ORIGIN, origin );
        }
        response.headers().add( Names.SEC_WEBSOCKET_LOCATION, getWebSocketLocation( request ) );

        String protocol = request.headers().get( Names.SEC_WEBSOCKET_PROTOCOL );

        if (protocol != null) {
            response.headers().add( Names.SEC_WEBSOCKET_PROTOCOL, protocol );
        }

        String key = request.headers().get( "Sec-WebSocket-Key" );
        String solution = Ietf07WebSocketChallenge.solve( key );

        response.headers().add( "Sec-WebSocket-Accept", solution );
        response.setChunked( false );

        return response;
    }

    @Override
    public boolean isComplete(HttpResponse response) throws Exception {
        log.debugf( "COMPLETE? " + response );
        String challengeResponse = response.headers().get( "Sec-WebSocket-Accept" );
        return this.challenge.verify( challengeResponse );
    }

    @Override
    public ChannelHandler newEncoder() {
        return new Ietf07WebSocketFrameEncoder( this.isClient );
    }

    @Override
    public ChannelHandler newDecoder() {
        return new Ietf07WebSocketFrameDecoder();
    }

    public ChannelHandler[] newAdditionalHandlers() {
        return new ChannelHandler[] {
                new PingHandler(),
        };
    }

    public int readResponseBody() {
        return 0;
    }

    private boolean isClient;
    private Ietf07WebSocketChallenge challenge;


}