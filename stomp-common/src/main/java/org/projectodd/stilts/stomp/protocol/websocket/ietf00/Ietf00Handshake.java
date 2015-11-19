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

package org.projectodd.stilts.stomp.protocol.websocket.ietf00;

import java.net.URI;
import java.security.NoSuchAlgorithmException;

import org.jboss.netty.buffer.ChannelBuffer;
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
public class Ietf00Handshake extends Handshake {


    public Ietf00Handshake() throws NoSuchAlgorithmException {
        super( "0" );
        this.challenge = new Ietf00WebSocketChallenge();
    }

    public boolean matches(HttpRequest request) {
        return (request.headers().contains( Names.SEC_WEBSOCKET_KEY1 ) && request.headers().contains( Names.SEC_WEBSOCKET_KEY2 ));
    }
    
    public HttpRequest generateRequest(URI uri) throws Exception {
        HttpRequest request = new DefaultHttpRequest( HttpVersion.HTTP_1_1, HttpMethod.GET, uri.toString() );

        request.headers().add( HttpHeaders.Names.CONNECTION, "Upgrade" );
        request.headers().add( HttpHeaders.Names.UPGRADE, "WebSocket" );
        request.headers().add( HttpHeaders.Names.HOST, uri.getHost()+ ":" + uri.getPort() );
        request.headers().add( HttpHeaders.Names.SEC_WEBSOCKET_PROTOCOL, "stomp" );

        request.headers().add( HttpHeaders.Names.SEC_WEBSOCKET_KEY1, this.challenge.getKey1String() );
        request.headers().add( HttpHeaders.Names.SEC_WEBSOCKET_KEY2, this.challenge.getKey2String() );

        ChannelBuffer buffer = ChannelBuffers.dynamicBuffer( 6 );
        buffer.writeBytes( challenge.getKey3() );
        buffer.writeByte( '\r' );
        buffer.writeByte( '\n' );

        request.setContent( buffer );
        
        return request;
    }

    @Override
    public HttpResponse generateResponse(HttpRequest request) throws Exception {
        HttpResponse response = new DefaultHttpResponse( HttpVersion.HTTP_1_1, new HttpResponseStatus( 101, "Web Socket Protocol Handshake - IETF-00" ) );

        String origin = request.headers().get( Names.ORIGIN );

        if (origin != null) {
            response.headers().add( Names.SEC_WEBSOCKET_ORIGIN, request.headers().get( Names.ORIGIN ) );
        }
        response.headers().add( Names.SEC_WEBSOCKET_LOCATION, getWebSocketLocation( request ) );

        String protocol = request.headers().get( Names.SEC_WEBSOCKET_PROTOCOL );

        if (protocol != null) {
            response.headers().add( Names.SEC_WEBSOCKET_PROTOCOL, protocol );
        }

        // Calculate the answer of the challenge.
        String key1 = request.headers().get( Names.SEC_WEBSOCKET_KEY1 );
        String key2 = request.headers().get( Names.SEC_WEBSOCKET_KEY2 );
        byte[] key3 = new byte[8];
        request.getContent().readBytes( key3 );
        
        byte[] solution = Ietf00WebSocketChallenge.solve( key1, key2, key3 );
        
        ChannelBuffer buffer = ChannelBuffers.dynamicBuffer( solution.length + 2 );
        buffer.writeBytes( solution );

        response.setContent( buffer );
        response.setChunked( false );

        return response;
    }
    
    public boolean isComplete(HttpResponse response) throws Exception {
        ChannelBuffer content = response.getContent();
        
        byte[] challengeResponse = new byte[16];
        content.readBytes( challengeResponse );

        return this.challenge.verify( challengeResponse );
    }
    
    public ChannelHandler newEncoder() {
        return new Ietf00WebSocketFrameEncoder();
    }
    
    public ChannelHandler newDecoder() {
        return new Ietf00WebSocketFrameDecoder();
    }
    
    public ChannelHandler[] newAdditionalHandlers() {
        return EMPTY_HANDLER_ARRAY;
    }
    
    public int readResponseBody() {
        return 16;
    }
        
    private static final ChannelHandler[] EMPTY_HANDLER_ARRAY = new ChannelHandler[0];
    private Ietf00WebSocketChallenge challenge;
}