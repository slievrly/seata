/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.seata.core.rpc.netty;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeoutException;

import io.netty.channel.Channel;
import io.netty.channel.ChannelDuplexHandler;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelPromise;
import io.netty.handler.codec.DecoderException;
import io.netty.handler.timeout.IdleState;
import io.netty.handler.timeout.IdleStateEvent;
import org.apache.seata.common.util.NetUtil;
import org.apache.seata.common.util.StringUtils;
import org.apache.seata.core.protocol.AbstractMessage;
import org.apache.seata.core.protocol.HeartbeatMessage;
import org.apache.seata.core.protocol.MergedWarpMessage;
import org.apache.seata.core.protocol.ProtocolConstants;
import org.apache.seata.core.protocol.RpcMessage;
import org.apache.seata.core.protocol.Version;
import org.apache.seata.core.rpc.RemotingServer;
import org.apache.seata.core.rpc.RpcContext;
import org.apache.seata.core.rpc.processor.Pair;
import org.apache.seata.core.rpc.processor.RemotingProcessor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The type abstract remoting server.
 *
 * @since 1.3.0
 */
public abstract class AbstractNettyRemotingServer extends AbstractNettyRemoting implements RemotingServer {

    private static final Logger LOGGER = LoggerFactory.getLogger(AbstractNettyRemotingServer.class);

    private final NettyServerBootstrap serverBootstrap;

    @Override
    public void init() {
        super.init();
        serverBootstrap.start();
    }

    public AbstractNettyRemotingServer(ThreadPoolExecutor messageExecutor, NettyServerConfig nettyServerConfig) {
        super(messageExecutor);
        serverBootstrap = new NettyServerBootstrap(nettyServerConfig);
        serverBootstrap.setChannelHandlers(new ServerHandler());
    }

    @Override
    public Object sendSyncRequest(String resourceId, String clientId, Object msg, boolean tryOtherApp)
        throws TimeoutException {
        Channel channel = ChannelManager.getChannel(resourceId, clientId, tryOtherApp);
        if (channel == null) {
            throw new RuntimeException("rm client is not connected. dbkey:" + resourceId + ",clientId:" + clientId);
        }
        RpcMessage rpcMessage = buildRequestMessage(msg, ProtocolConstants.MSGTYPE_RESQUEST_SYNC);
        return super.sendSync(channel, rpcMessage, NettyServerConfig.getRpcRequestTimeout());
    }

    @Override
    public Object sendSyncRequest(Channel channel, Object msg) throws TimeoutException {
        if (channel == null) {
            throw new RuntimeException("client is not connected");
        }
        RpcMessage rpcMessage = buildRequestMessage(msg, ProtocolConstants.MSGTYPE_RESQUEST_SYNC);
        return super.sendSync(channel, rpcMessage, NettyServerConfig.getRpcRequestTimeout());
    }

    @Override
    public void sendAsyncRequest(Channel channel, Object msg) {
        if (channel == null) {
            throw new RuntimeException("client is not connected");
        }
        RpcMessage rpcMessage = buildRequestMessage(msg, ProtocolConstants.MSGTYPE_RESQUEST_ONEWAY);
        super.sendAsync(channel, rpcMessage);
    }

    @Override
    public void sendAsyncResponse(RpcMessage rpcMessage, Channel channel, Object msg) {
        Channel clientChannel = channel;
        if (!(msg instanceof HeartbeatMessage)) {
            clientChannel = ChannelManager.getSameClientChannel(channel);
        }
        if (clientChannel != null) {
            RpcMessage rpcMsg = buildResponseMessage(rpcMessage, msg, msg instanceof HeartbeatMessage
                ? ProtocolConstants.MSGTYPE_HEARTBEAT_RESPONSE
                : ProtocolConstants.MSGTYPE_RESPONSE);
            super.sendAsync(clientChannel, rpcMsg);
        } else {
            throw new RuntimeException("channel is error.");
        }
    }


    @Override
    public void registerProcessor(int messageType, RemotingProcessor processor, ExecutorService executor) {
        Pair<RemotingProcessor, ExecutorService> pair = new Pair<>(processor, executor);
        this.processorTable.put(messageType, pair);
    }

    /**
     * Gets listen port.
     *
     * @return the listen port
     */
    public int getListenPort() {
        return serverBootstrap.getListenPort();
    }

    @Override
    public void destroy() {
        serverBootstrap.shutdown();
        super.destroy();
    }

    /**
     * Debug log.
     *
     * @param format the info
     * @param arguments the arguments
     */
    protected void debugLog(String format, Object... arguments) {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug(format, arguments);
        }
    }

    private void closeChannelHandlerContext(ChannelHandlerContext ctx) {
        if (LOGGER.isInfoEnabled()) {
            LOGGER.info("closeChannelHandlerContext channel:" + ctx.channel());
        }
        ctx.disconnect();
        ctx.close();
    }

    /**
     * The type ServerHandler.
     */
    @ChannelHandler.Sharable
    class ServerHandler extends ChannelDuplexHandler {

        /**
         * Channel read.
         *
         * @param ctx the ctx
         * @param msg the msg
         * @throws Exception the exception
         */
        @Override
        public void channelRead(final ChannelHandlerContext ctx, Object msg) throws Exception {
            if (msg instanceof RpcMessage) {
                processMessage(ctx, (RpcMessage)msg);
            } else {
                LOGGER.error("rpcMessage type error");
            }
        }

        @Override
        public void channelWritabilityChanged(ChannelHandlerContext ctx) {
            synchronized (lock) {
                if (ctx.channel().isWritable()) {
                    lock.notifyAll();
                }
            }
            ctx.fireChannelWritabilityChanged();
        }

        /**
         * Channel inactive.
         *
         * @param ctx the ctx
         * @throws Exception the exception
         */
        @Override
        public void channelInactive(ChannelHandlerContext ctx) throws Exception {
            debugLog("inactive:{}", ctx);
            if (messageExecutor.isShutdown()) {
                return;
            }
            handleDisconnect(ctx);
            super.channelInactive(ctx);
        }

        private void handleDisconnect(ChannelHandlerContext ctx) {
            final String ipAndPort = NetUtil.toStringAddress(ctx.channel().remoteAddress());
            RpcContext rpcContext = ChannelManager.getContextFromIdentified(ctx.channel());
            if (LOGGER.isInfoEnabled()) {
                LOGGER.info(ipAndPort + " to server channel inactive.");
            }
            if (rpcContext != null && rpcContext.getClientRole() != null) {
                rpcContext.release();
                if (LOGGER.isInfoEnabled()) {
                    LOGGER.info("remove channel:" + ctx.channel() + "context:" + rpcContext);
                }
            } else {
                if (LOGGER.isInfoEnabled()) {
                    LOGGER.info("remove unused channel:" + ctx.channel());
                }
            }
        }

        /**
         * Exception caught.
         *
         * @param ctx   the ctx
         * @param cause the cause
         * @throws Exception the exception
         */
        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
            try {
                if (cause instanceof DecoderException && null == ChannelManager.getContextFromIdentified(ctx.channel())) {
                    return;
                }
                LOGGER.error("exceptionCaught:{}, channel:{}", cause.getMessage(), ctx.channel());
                super.exceptionCaught(ctx, cause);
            } finally {
                ChannelManager.releaseRpcContext(ctx.channel());
            }
        }

        /**
         * User event triggered.
         *
         * @param ctx the ctx
         * @param evt the evt
         * @throws Exception the exception
         */
        @Override
        public void userEventTriggered(ChannelHandlerContext ctx, Object evt) {
            if (evt instanceof IdleStateEvent) {
                debugLog("idle:{}", evt);
                IdleStateEvent idleStateEvent = (IdleStateEvent) evt;
                if (idleStateEvent.state() == IdleState.READER_IDLE) {
                    if (LOGGER.isInfoEnabled()) {
                        LOGGER.info("channel:" + ctx.channel() + " read idle.");
                    }
                    handleDisconnect(ctx);
                    try {
                        closeChannelHandlerContext(ctx);
                    } catch (Exception e) {
                        LOGGER.error(e.getMessage());
                    }
                }
            }
        }

        @Override
        public void close(ChannelHandlerContext ctx, ChannelPromise future) throws Exception {
            if (LOGGER.isInfoEnabled()) {
                LOGGER.info(ctx + " will closed");
            }
            super.close(ctx, future);
        }

    }

    @Override
    protected void processMessage(ChannelHandlerContext ctx, RpcMessage rpcMessage) throws Exception {
        Object body = rpcMessage.getBody();
        RpcContext rpcContext = ChannelManager.getContextFromIdentified(ctx.channel());
        // If the client is not version 2.3.0 or higher, splitting MergedWarpMessage will result in the client’s mergeMsgMap not being cleared
        if (body instanceof MergedWarpMessage && (StringUtils.isNotBlank(rpcContext.getVersion())
            && Version.isAboveOrEqualVersion230(rpcContext.getVersion()))) {
            MergedWarpMessage mergedWarpMessage = (MergedWarpMessage)body;
            for (int i = 0; i < mergedWarpMessage.msgs.size(); i++) {
                RpcMessage rpcMsg =
                    buildRequestMessage(mergedWarpMessage.msgs.get(i), rpcMessage, mergedWarpMessage.msgIds.get(i));
                super.processMessage(ctx, rpcMsg);
            }
        } else {
            super.processMessage(ctx, rpcMessage);
        }
    }

    private RpcMessage buildRequestMessage(AbstractMessage msg, RpcMessage rpcMessage,int id) {
        RpcMessage rpcMsg = new RpcMessage();
        rpcMsg.setId(id);
        rpcMsg.setCodec(rpcMessage.getCodec());
        rpcMsg.setCompressor(rpcMessage.getCompressor());
        rpcMsg.setBody(msg);
        return rpcMsg;
    }

}
