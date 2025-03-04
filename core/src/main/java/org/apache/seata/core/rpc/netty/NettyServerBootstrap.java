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

import java.net.InetSocketAddress;
import java.net.SocketException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.WriteBufferWaterMark;
import io.netty.channel.epoll.EpollEventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.handler.timeout.IdleStateHandler;
import org.apache.seata.common.ConfigurationKeys;
import org.apache.seata.common.XID;
import org.apache.seata.common.metadata.Instance;
import org.apache.seata.common.metadata.Node;
import org.apache.seata.common.thread.NamedThreadFactory;
import org.apache.seata.config.ConfigurationFactory;
import org.apache.seata.core.rpc.RemotingBootstrap;
import org.apache.seata.discovery.registry.MultiRegistryFactory;
import org.apache.seata.discovery.registry.RegistryService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.apache.seata.common.DefaultValues.SERVICE_DEFAULT_PORT;

/**
 * Rpc server bootstrap.
 *
 * @since 1.1.0
 */
public class NettyServerBootstrap implements RemotingBootstrap {

    private static final Logger LOGGER = LoggerFactory.getLogger(NettyServerBootstrap.class);
    private final ServerBootstrap serverBootstrap = new ServerBootstrap();
    private final EventLoopGroup eventLoopGroupWorker;
    private final EventLoopGroup eventLoopGroupBoss;
    private final NettyServerConfig nettyServerConfig;
    private ChannelHandler[] channelHandlers;
    private int listenPort;
    private final AtomicBoolean initialized = new AtomicBoolean(false);

    public NettyServerBootstrap(NettyServerConfig nettyServerConfig) {
        this.nettyServerConfig = nettyServerConfig;
        if (NettyServerConfig.enableEpoll()) {
            this.eventLoopGroupBoss = new EpollEventLoopGroup(nettyServerConfig.getBossThreadSize(),
                new NamedThreadFactory(nettyServerConfig.getBossThreadPrefix(), nettyServerConfig.getBossThreadSize()));
            this.eventLoopGroupWorker = new EpollEventLoopGroup(nettyServerConfig.getServerWorkerThreads(),
                new NamedThreadFactory(nettyServerConfig.getWorkerThreadPrefix(),
                    nettyServerConfig.getServerWorkerThreads()));
        } else {
            this.eventLoopGroupBoss = new NioEventLoopGroup(nettyServerConfig.getBossThreadSize(),
                new NamedThreadFactory(nettyServerConfig.getBossThreadPrefix(), nettyServerConfig.getBossThreadSize()));
            this.eventLoopGroupWorker = new NioEventLoopGroup(nettyServerConfig.getServerWorkerThreads(),
                new NamedThreadFactory(nettyServerConfig.getWorkerThreadPrefix(),
                    nettyServerConfig.getServerWorkerThreads()));
        }

        if (nettyServerConfig.getServerListenPort() > 0) {
            setListenPort(nettyServerConfig.getServerListenPort());
        }
    }

    /**
     * Sets channel handlers.
     *
     * @param handlers the handlers
     */
    protected void setChannelHandlers(final ChannelHandler... handlers) {
        if (handlers != null) {
            channelHandlers = handlers;
        }
    }

    protected ChannelHandler[] getChannelHandlers() {
        return channelHandlers;
    }

    /**
     * Add channel pipeline last.
     *
     * @param channel  the channel
     * @param handlers the handlers
     */
    private void addChannelPipelineLast(Channel channel, ChannelHandler... handlers) {
        if (channel != null && handlers != null) {
            channel.pipeline().addLast(handlers);
        }
    }

    /**
     * use for mock
     *
     * @param listenPort the listen port
     */
    public void setListenPort(int listenPort) {
        if (listenPort <= 0) {
            throw new IllegalArgumentException("listen port: " + listenPort + " is invalid!");
        }
        this.listenPort = listenPort;
    }

    /**
     * Gets listen port.
     *
     * @return the listen port
     */
    public int getListenPort() {
        if (listenPort != 0) {
            return listenPort;
        }
        String strPort = ConfigurationFactory.getInstance().getConfig(ConfigurationKeys.SERVER_SERVICE_PORT_CAMEL);
        int port = 0;
        try {
            port = Integer.parseInt(strPort);
        } catch (NumberFormatException exx) {
            LOGGER.error("server service port set error:{}", exx.getMessage());
        }
        if (port <= 0) {
            LOGGER.error("listen port: {} is invalid, will use default port:{}", port, SERVICE_DEFAULT_PORT);
            port = SERVICE_DEFAULT_PORT;
        }
        listenPort = port;
        return port;
    }

    @Override
    public void start() {
        int port = getListenPort();
        this.serverBootstrap.group(this.eventLoopGroupBoss, this.eventLoopGroupWorker)
            .channel(NettyServerConfig.SERVER_CHANNEL_CLAZZ)
            .option(ChannelOption.SO_BACKLOG, nettyServerConfig.getSoBackLogSize())
            .option(ChannelOption.SO_REUSEADDR, true)
            .childOption(ChannelOption.SO_KEEPALIVE, true)
            .childOption(ChannelOption.TCP_NODELAY, true)
            .childOption(ChannelOption.SO_SNDBUF, nettyServerConfig.getServerSocketSendBufSize())
            .childOption(ChannelOption.SO_RCVBUF, nettyServerConfig.getServerSocketResvBufSize())
            .childOption(ChannelOption.WRITE_BUFFER_WATER_MARK,
                new WriteBufferWaterMark(nettyServerConfig.getWriteBufferLowWaterMark(),
                    nettyServerConfig.getWriteBufferHighWaterMark()))
            .localAddress(new InetSocketAddress(port))
            .childHandler(new ChannelInitializer<SocketChannel>() {
                @Override
                public void initChannel(SocketChannel ch) {
                    ch.pipeline().addLast(new IdleStateHandler(nettyServerConfig.getChannelMaxReadIdleSeconds(), 0, 0))
                            .addLast(new ProtocolDetectHandler(NettyServerBootstrap.this));
                }
            });

        try {
            this.serverBootstrap.bind(port).sync();
            LOGGER.info("Server started, service listen port: {}", getListenPort());
            Instance instance = Instance.getInstance();
            // Lines 177-180 are just for compatibility with test cases
            if (instance.getTransaction() == null) {
                Instance.getInstance().setTransaction(new Node.Endpoint(XID.getIpAddress(), XID.getPort(), "netty"));
            }
            for (RegistryService<?> registryService : MultiRegistryFactory.getInstances()) {
                registryService.register(Instance.getInstance());
            }
            initialized.set(true);
        } catch (SocketException se) {
            throw new RuntimeException("Server start failed, the listen port: " + getListenPort(), se);
        } catch (Exception exx) {
            throw new RuntimeException("Server start failed", exx);
        }
    }

    @Override
    public void shutdown() {
        try {
            if (LOGGER.isInfoEnabled()) {
                LOGGER.info("Shutting server down, the listen port: {}", XID.getPort());
            }
            if (initialized.get()) {
                for (RegistryService registryService : MultiRegistryFactory.getInstances()) {
                    registryService.unregister(Instance.getInstance());
                    registryService.close();
                }
                //wait a few seconds for server transport
                TimeUnit.SECONDS.sleep(nettyServerConfig.getServerShutdownWaitTime());
            }

            this.eventLoopGroupBoss.shutdownGracefully();
            this.eventLoopGroupWorker.shutdownGracefully();
        } catch (Exception exx) {
            LOGGER.error("shutdown execute error: {}", exx.getMessage(), exx);
        }
    }
}
