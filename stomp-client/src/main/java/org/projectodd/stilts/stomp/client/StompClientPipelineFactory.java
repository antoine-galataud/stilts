/*
 * Copyright 2011 Red Hat, Inc, and individual contributors.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.projectodd.stilts.stomp.client;

import org.jboss.netty.channel.ChannelPipeline;
import org.jboss.netty.channel.ChannelPipelineFactory;
import org.jboss.netty.channel.Channels;
import org.jboss.netty.handler.codec.http.HttpRequestDecoder;
import org.jboss.netty.handler.codec.http.HttpRequestEncoder;
import org.jboss.netty.handler.codec.http.HttpResponseDecoder;
import org.jboss.netty.handler.codec.http.websocket.WebSocketFrameDecoder;
import org.jboss.netty.handler.codec.http.websocket.WebSocketFrameEncoder;
import org.projectodd.stilts.stomp.client.protocol.ClientContext;
import org.projectodd.stilts.stomp.client.protocol.ClientMessageHandler;
import org.projectodd.stilts.stomp.client.protocol.ClientReceiptHandler;
import org.projectodd.stilts.stomp.client.protocol.ConnectedHandler;
import org.projectodd.stilts.stomp.client.protocol.websockets.WebSocketConnectionNegotiator;
import org.projectodd.stilts.stomp.protocol.DebugHandler;
import org.projectodd.stilts.stomp.protocol.StompFrameDecoder;
import org.projectodd.stilts.stomp.protocol.StompFrameEncoder;
import org.projectodd.stilts.stomp.protocol.StompMessageDecoder;
import org.projectodd.stilts.stomp.protocol.StompMessageEncoder;

public class StompClientPipelineFactory implements ChannelPipelineFactory {

    public StompClientPipelineFactory(StompClient client, ClientContext clientContext, boolean useWebSockets) {
        this.client = client;
        this.clientContext = clientContext;
        this.useWebSockets = useWebSockets;
    }

    @Override
    public ChannelPipeline getPipeline() throws Exception {
        ChannelPipeline pipeline = Channels.pipeline();

        // pipeline.addLast( "debug-head", new DebugHandler());

        if (this.useWebSockets) {
            pipeline.addLast( "http-response-decoder", new HttpResponseDecoder() );
            pipeline.addLast( "http-request-encoder", new HttpRequestEncoder() );
            pipeline.addLast( "websocket-frame-decoder", new WebSocketFrameDecoder() );
            pipeline.addLast( "websocket-frame-encoder", new WebSocketFrameEncoder() );
            pipeline.addLast( "websocket-connection-negotiator", new WebSocketConnectionNegotiator() );
        }

        pipeline.addLast( "stomp-frame-decoder", new StompFrameDecoder() );
        pipeline.addLast( "stomp-frame-encoder", new StompFrameEncoder() );
        pipeline.addLast( "debug-frame-encoders", new DebugHandler() );

        pipeline.addLast( "stomp-client-connect", new ConnectedHandler( clientContext ) );
        pipeline.addLast( "stomp-client-receipt", new ClientReceiptHandler( clientContext ) );

        pipeline.addLast( "stomp-message-encoder", new StompMessageEncoder() );
        pipeline.addLast( "stomp-message-decoder", new StompMessageDecoder( new ClientStompMessageFactory( this.client ) ) );
        pipeline.addLast( "debug-message-encoders", new DebugHandler() );

        pipeline.addLast( "stomp-client-message-handler", new ClientMessageHandler( clientContext ) );

        return pipeline;
    }

    private StompClient client;
    private ClientContext clientContext;
    private boolean useWebSockets;

}