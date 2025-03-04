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

import java.util.Map;
import java.util.Set;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Function;

import io.netty.channel.Channel;
import io.netty.util.concurrent.EventExecutorGroup;
import org.apache.seata.common.DefaultValues;
import org.apache.seata.common.exception.FrameworkErrorCode;
import org.apache.seata.common.exception.FrameworkException;
import org.apache.seata.common.thread.NamedThreadFactory;
import org.apache.seata.common.util.StringUtils;
import org.apache.seata.config.CachedConfigurationChangeListener;
import org.apache.seata.config.Configuration;
import org.apache.seata.config.ConfigurationChangeEvent;
import org.apache.seata.config.ConfigurationFactory;
import org.apache.seata.core.constants.ConfigurationKeys;
import org.apache.seata.core.model.Resource;
import org.apache.seata.core.model.ResourceManager;
import org.apache.seata.core.protocol.AbstractMessage;
import org.apache.seata.core.protocol.MessageType;
import org.apache.seata.core.protocol.RegisterRMRequest;
import org.apache.seata.core.protocol.RegisterRMResponse;
import org.apache.seata.core.rpc.netty.NettyPoolKey.TransactionRole;
import org.apache.seata.core.rpc.processor.client.ClientHeartbeatProcessor;
import org.apache.seata.core.rpc.processor.client.ClientOnResponseProcessor;
import org.apache.seata.core.rpc.processor.client.RmBranchCommitProcessor;
import org.apache.seata.core.rpc.processor.client.RmBranchRollbackProcessor;
import org.apache.seata.core.rpc.processor.client.RmUndoLogProcessor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.apache.seata.common.Constants.DBKEYS_SPLIT_CHAR;

/**
 * The Rm netty client.
 *
 */

public final class RmNettyRemotingClient extends AbstractNettyRemotingClient {

    private static final Logger LOGGER = LoggerFactory.getLogger(RmNettyRemotingClient.class);
    private ResourceManager resourceManager;
    private static volatile RmNettyRemotingClient instance;
    private final AtomicBoolean initialized = new AtomicBoolean(false);
    private static final long KEEP_ALIVE_TIME = Integer.MAX_VALUE;
    private static final int MAX_QUEUE_SIZE = 20000;
    private String applicationId;
    private String transactionServiceGroup;

    @Override
    public void init() {
        // registry processor
        registerProcessor();
        if (initialized.compareAndSet(false, true)) {
            super.init();

            // Found one or more resources that were registered before initialization
            if (resourceManager != null
                    && !resourceManager.getManagedResources().isEmpty()
                    && StringUtils.isNotBlank(transactionServiceGroup)) {
                boolean failFast = ConfigurationFactory.getInstance().getBoolean(
                        ConfigurationKeys.ENABLE_RM_CLIENT_CHANNEL_CHECK_FAIL_FAST,
                        DefaultValues.DEFAULT_CLIENT_CHANNEL_CHECK_FAIL_FAST);
                getClientChannelManager().initReconnect(transactionServiceGroup, failFast);
            }
        }
    }

    private RmNettyRemotingClient(NettyClientConfig nettyClientConfig, EventExecutorGroup eventExecutorGroup,
                                  ThreadPoolExecutor messageExecutor) {
        super(nettyClientConfig, eventExecutorGroup, messageExecutor, TransactionRole.RMROLE);
        // set enableClientBatchSendRequest
        Configuration configuration = ConfigurationFactory.getInstance();
        this.enableClientBatchSendRequest = configuration.getBoolean(ConfigurationKeys.ENABLE_RM_CLIENT_BATCH_SEND_REQUEST,
                ConfigurationFactory.getInstance().getBoolean(ConfigurationKeys.ENABLE_CLIENT_BATCH_SEND_REQUEST,DefaultValues.DEFAULT_ENABLE_RM_CLIENT_BATCH_SEND_REQUEST));
        configuration.addConfigListener(ConfigurationKeys.ENABLE_RM_CLIENT_BATCH_SEND_REQUEST, new CachedConfigurationChangeListener() {
            @Override
            public void onChangeEvent(ConfigurationChangeEvent event) {
                String dataId = event.getDataId();
                String newValue = event.getNewValue();
                if (ConfigurationKeys.ENABLE_RM_CLIENT_BATCH_SEND_REQUEST.equals(dataId) && StringUtils.isNotBlank(newValue)) {
                    enableClientBatchSendRequest = Boolean.parseBoolean(newValue);
                }
            }
        });
    }

    /**
     * Gets instance.
     *
     * @param applicationId           the application id
     * @param transactionServiceGroup the transaction service group
     * @return the instance
     */
    public static RmNettyRemotingClient getInstance(String applicationId, String transactionServiceGroup) {
        RmNettyRemotingClient rmNettyRemotingClient = getInstance();
        rmNettyRemotingClient.setApplicationId(applicationId);
        rmNettyRemotingClient.setTransactionServiceGroup(transactionServiceGroup);
        return rmNettyRemotingClient;
    }

    /**
     * Gets instance.
     *
     * @return the instance
     */
    public static RmNettyRemotingClient getInstance() {
        if (instance == null) {
            synchronized (RmNettyRemotingClient.class) {
                if (instance == null) {
                    NettyClientConfig nettyClientConfig = new NettyClientConfig();
                    final ThreadPoolExecutor messageExecutor = new ThreadPoolExecutor(
                        nettyClientConfig.getClientWorkerThreads(), nettyClientConfig.getClientWorkerThreads(),
                        KEEP_ALIVE_TIME, TimeUnit.SECONDS, new LinkedBlockingQueue<>(MAX_QUEUE_SIZE),
                        new NamedThreadFactory(nettyClientConfig.getRmDispatchThreadPrefix(),
                            nettyClientConfig.getClientWorkerThreads()), new ThreadPoolExecutor.CallerRunsPolicy());
                    instance = new RmNettyRemotingClient(nettyClientConfig, null, messageExecutor);
                }
            }
        }
        return instance;
    }

    /**
     * Sets application id.
     *
     * @param applicationId the application id
     */
    public void setApplicationId(String applicationId) {
        this.applicationId = applicationId;
    }

    /**
     * Sets transaction service group.
     *
     * @param transactionServiceGroup the transaction service group
     */
    public void setTransactionServiceGroup(String transactionServiceGroup) {
        this.transactionServiceGroup = transactionServiceGroup;
    }

    /**
     * Sets resource manager.
     *
     * @param resourceManager the resource manager
     */
    public void setResourceManager(ResourceManager resourceManager) {
        this.resourceManager = resourceManager;
    }

    @Override
    public void onRegisterMsgSuccess(String serverAddress, Channel channel, Object response,
                                     AbstractMessage requestMessage) {
        RegisterRMRequest registerRMRequest = (RegisterRMRequest)requestMessage;
        RegisterRMResponse registerRMResponse = (RegisterRMResponse)response;
        if (LOGGER.isInfoEnabled()) {
            LOGGER.info("register RM success. client version:{}, server version:{},channel:{}", registerRMRequest.getVersion(), registerRMResponse.getVersion(), channel);
        }
        getClientChannelManager().registerChannel(serverAddress, channel);
        String dbKey = getMergedResourceKeys();
        if (registerRMRequest.getResourceIds() != null) {
            if (!registerRMRequest.getResourceIds().equals(dbKey)) {
                sendRegisterMessage(serverAddress, channel, dbKey);
            }
        }

    }

    @Override
    public void onRegisterMsgFail(String serverAddress, Channel channel, Object response,
                                  AbstractMessage requestMessage) {
        RegisterRMRequest registerRMRequest = (RegisterRMRequest)requestMessage;
        RegisterRMResponse registerRMResponse = (RegisterRMResponse)response;
        String errMsg = String.format(
            "register RM failed. client version: %s,server version: %s, errorMsg: %s, " + "channel: %s", registerRMRequest.getVersion(), registerRMResponse.getVersion(), registerRMResponse.getMsg(), channel);
        throw new FrameworkException(errMsg);
    }

    /**
     * Register new db key.
     *
     * @param resourceGroupId the resource group id
     * @param resourceId      the db key
     */
    public void registerResource(String resourceGroupId, String resourceId) {

        // Resource registration cannot be performed until the RM client is initialized
        if (StringUtils.isBlank(transactionServiceGroup)) {
            return;
        }

        // ResourceId can not be null or empty
        if (StringUtils.isBlank(resourceId)) {
            LOGGER.warn("The resourceId must not be null or empty when registering the RM client.");
            return;
        }

        if (getClientChannelManager().getChannels().isEmpty()) {
            boolean failFast = ConfigurationFactory.getInstance().getBoolean(
                    ConfigurationKeys.ENABLE_RM_CLIENT_CHANNEL_CHECK_FAIL_FAST,
                    DefaultValues.DEFAULT_CLIENT_CHANNEL_CHECK_FAIL_FAST);
            getClientChannelManager().initReconnect(transactionServiceGroup, failFast);
            return;
        }
        synchronized (getClientChannelManager().getChannels()) {
            for (Map.Entry<String, Channel> entry : getClientChannelManager().getChannels().entrySet()) {
                String serverAddress = entry.getKey();
                Channel rmChannel = entry.getValue();
                if (LOGGER.isInfoEnabled()) {
                    LOGGER.info("will register resourceId:{}", resourceId);
                }
                sendRegisterMessage(serverAddress, rmChannel, resourceId);
            }
        }
    }

    public void sendRegisterMessage(String serverAddress, Channel channel, String resourceId) {
        RegisterRMRequest message = new RegisterRMRequest(applicationId, transactionServiceGroup);
        message.setResourceIds(resourceId);
        try {
            super.sendAsyncRequest(channel, message);
        } catch (FrameworkException e) {
            if (e.getErrcode() == FrameworkErrorCode.ChannelIsNotWritable && serverAddress != null) {
                getClientChannelManager().releaseChannel(channel, serverAddress);
                if (LOGGER.isInfoEnabled()) {
                    LOGGER.info("remove not writable channel:{}", channel);
                }
            } else {
                LOGGER.error("register resource failed, channel:{},resourceId:{}", channel, resourceId, e);
            }
        }
    }

    public String getMergedResourceKeys() {
        Map<String, Resource> managedResources = resourceManager.getManagedResources();
        Set<String> resourceIds = managedResources.keySet();
        if (!resourceIds.isEmpty()) {
            StringBuilder sb = new StringBuilder();
            boolean first = true;
            for (String resourceId : resourceIds) {
                if (StringUtils.isBlank(resourceId)) {
                    LOGGER.warn("The resourceId must not be null or empty when registering the RM client.");
                    continue;
                }
                if (first) {
                    first = false;
                } else {
                    sb.append(DBKEYS_SPLIT_CHAR);
                }
                sb.append(resourceId);
            }
            return sb.toString();
        }
        return null;
    }

    @Override
    public void destroy() {
        super.destroy();
        initialized.getAndSet(false);
        instance = null;
    }

    @Override
    protected Function<String, NettyPoolKey> getPoolKeyFunction() {
        return serverAddress -> {
            String resourceIds = getMergedResourceKeys();
            if (resourceIds != null && LOGGER.isInfoEnabled()) {
                LOGGER.info("RM will register :{}", resourceIds);
            }
            RegisterRMRequest message = new RegisterRMRequest(applicationId, transactionServiceGroup);
            message.setResourceIds(resourceIds);
            return new NettyPoolKey(NettyPoolKey.TransactionRole.RMROLE, serverAddress, message);
        };
    }

    @Override
    protected String getTransactionServiceGroup() {
        return transactionServiceGroup;
    }

    @Override
    public boolean isEnableClientBatchSendRequest() {
        return enableClientBatchSendRequest;
    }

    @Override
    public long getRpcRequestTimeout() {
        return NettyClientConfig.getRpcRmRequestTimeout();
    }

    private void registerProcessor() {
        // 1.registry rm client handle branch commit processor
        RmBranchCommitProcessor rmBranchCommitProcessor = new RmBranchCommitProcessor(getTransactionMessageHandler(), this);
        super.registerProcessor(MessageType.TYPE_BRANCH_COMMIT, rmBranchCommitProcessor, messageExecutor);
        // 2.registry rm client handle branch rollback processor
        RmBranchRollbackProcessor rmBranchRollbackProcessor = new RmBranchRollbackProcessor(getTransactionMessageHandler(), this);
        super.registerProcessor(MessageType.TYPE_BRANCH_ROLLBACK, rmBranchRollbackProcessor, messageExecutor);
        // 3.registry rm handler undo log processor
        RmUndoLogProcessor rmUndoLogProcessor = new RmUndoLogProcessor(getTransactionMessageHandler());
        super.registerProcessor(MessageType.TYPE_RM_DELETE_UNDOLOG, rmUndoLogProcessor, messageExecutor);
        // 4.registry TC response processor
        ClientOnResponseProcessor onResponseProcessor =
            new ClientOnResponseProcessor(mergeMsgMap, super.getFutures(), childToParentMap, getTransactionMessageHandler());
        super.registerProcessor(MessageType.TYPE_SEATA_MERGE_RESULT, onResponseProcessor, null);
        super.registerProcessor(MessageType.TYPE_BRANCH_REGISTER_RESULT, onResponseProcessor, null);
        super.registerProcessor(MessageType.TYPE_BRANCH_STATUS_REPORT_RESULT, onResponseProcessor, null);
        super.registerProcessor(MessageType.TYPE_GLOBAL_LOCK_QUERY_RESULT, onResponseProcessor, null);
        super.registerProcessor(MessageType.TYPE_REG_RM_RESULT, onResponseProcessor, null);
        super.registerProcessor(MessageType.TYPE_BATCH_RESULT_MSG, onResponseProcessor, null);
        // 5.registry heartbeat message processor
        ClientHeartbeatProcessor clientHeartbeatProcessor = new ClientHeartbeatProcessor();
        super.registerProcessor(MessageType.TYPE_HEARTBEAT_MSG, clientHeartbeatProcessor, null);
    }
}
