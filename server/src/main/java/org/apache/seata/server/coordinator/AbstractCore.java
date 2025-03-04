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
package org.apache.seata.server.coordinator;

import java.io.IOException;
import java.util.concurrent.TimeoutException;

import org.apache.seata.common.ConfigurationKeys;
import org.apache.seata.common.DefaultValues;
import org.apache.seata.common.util.StringUtils;
import org.apache.seata.config.Configuration;
import org.apache.seata.config.ConfigurationFactory;
import org.apache.seata.core.context.RootContext;
import org.apache.seata.core.exception.BranchTransactionException;
import org.apache.seata.core.exception.GlobalTransactionException;
import org.apache.seata.core.exception.TransactionException;
import org.apache.seata.core.exception.TransactionExceptionCode;
import org.apache.seata.core.model.BranchStatus;
import org.apache.seata.core.model.BranchType;
import org.apache.seata.core.model.GlobalStatus;
import org.apache.seata.core.protocol.transaction.BranchCommitRequest;
import org.apache.seata.core.protocol.transaction.BranchCommitResponse;
import org.apache.seata.core.protocol.transaction.BranchRollbackRequest;
import org.apache.seata.core.protocol.transaction.BranchRollbackResponse;
import org.apache.seata.core.rpc.RemotingServer;
import org.apache.seata.server.lock.LockManager;
import org.apache.seata.server.lock.LockerManagerFactory;
import org.apache.seata.server.session.BranchSession;
import org.apache.seata.server.session.GlobalSession;
import org.apache.seata.server.session.SessionHelper;
import org.apache.seata.server.session.SessionHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import static org.apache.seata.core.exception.TransactionExceptionCode.BranchTransactionNotExist;
import static org.apache.seata.core.exception.TransactionExceptionCode.FailedToAddBranch;
import static org.apache.seata.core.exception.TransactionExceptionCode.GlobalTransactionNotActive;
import static org.apache.seata.core.exception.TransactionExceptionCode.GlobalTransactionStatusInvalid;
import static org.apache.seata.core.exception.TransactionExceptionCode.FailedToSendBranchCommitRequest;
import static org.apache.seata.core.exception.TransactionExceptionCode.FailedToSendBranchRollbackRequest;

/**
 * The type abstract core.
 *
 */
public abstract class AbstractCore implements Core {

    protected static final Logger LOGGER = LoggerFactory.getLogger(AbstractCore.class);

    protected LockManager lockManager = LockerManagerFactory.getLockManager();

    private static final Configuration CONFIG = ConfigurationFactory.getInstance();
    private int appDataErrSize ;
    private boolean throwDataSizeExp ;

    protected RemotingServer remotingServer;

    public AbstractCore(RemotingServer remotingServer) {
        if (remotingServer == null) {
            throw new IllegalArgumentException("remotingServer must be not null");
        }
        this.remotingServer = remotingServer;
        this.appDataErrSize = CONFIG.getInt(ConfigurationKeys.SERVER_APPLICATION_DATA_SIZE_LIMIT,
            DefaultValues.DEFAULT_APPLICATION_DATA_SIZE_LIMIT);
        this.throwDataSizeExp = CONFIG.getBoolean(ConfigurationKeys.SERVER_APPLICATION_DATA_SIZE_CHECK, false);

    }

    public abstract BranchType getHandleBranchType();

    @Override
    public Long branchRegister(BranchType branchType, String resourceId, String clientId, String xid,
                               String applicationData, String lockKeys) throws TransactionException {
        GlobalSession globalSession = assertGlobalSessionNotNull(xid, false);
        try {
            StringUtils.checkDataSize(applicationData, "applicationData", appDataErrSize, throwDataSizeExp);
        } catch (RuntimeException e) {
            throw new BranchTransactionException(TransactionExceptionCode.FailedToAddBranch,
                    String.format("Failed to store branch xid = %s ", globalSession.getXid()), e);
        }

        return SessionHolder.lockAndExecute(globalSession, () -> {
            globalSessionStatusCheck(globalSession);
            BranchSession branchSession = SessionHelper.newBranchByGlobal(globalSession, branchType, resourceId,
                    applicationData, lockKeys, clientId);
            MDC.put(RootContext.MDC_KEY_BRANCH_ID, String.valueOf(branchSession.getBranchId()));
            branchSessionLock(globalSession, branchSession);
            try {
                globalSession.addBranch(branchSession);
            } catch (RuntimeException ex) {
                branchSessionUnlock(branchSession);
                throw new BranchTransactionException(FailedToAddBranch, String
                        .format("Failed to store branch xid = %s branchId = %s", globalSession.getXid(),
                                branchSession.getBranchId()), ex);
            }
            if (LOGGER.isInfoEnabled()) {
                LOGGER.info("Register branch successfully, xid = {}, branchId = {}, resourceId = {} ,lockKeys = {}",
                    globalSession.getXid(), branchSession.getBranchId(), resourceId, lockKeys);
            }
            return branchSession.getBranchId();
        });
    }

    protected void globalSessionStatusCheck(GlobalSession globalSession) throws GlobalTransactionException {
        if (!globalSession.isActive()) {
            throw new GlobalTransactionException(GlobalTransactionNotActive, String.format(
                "Could not register branch into global session xid = %s status = %s, cause by globalSession not active",
                globalSession.getXid(), globalSession.getStatus()));
        }
        if (globalSession.getStatus() != GlobalStatus.Begin) {
            throw new GlobalTransactionException(GlobalTransactionStatusInvalid, String
                    .format("Could not register branch into global session xid = %s status = %s while expecting %s",
                            globalSession.getXid(), globalSession.getStatus(), GlobalStatus.Begin));
        }
    }

    protected void branchSessionLock(GlobalSession globalSession, BranchSession branchSession) throws TransactionException {

    }

    protected void branchSessionUnlock(BranchSession branchSession) throws TransactionException {

    }

    private GlobalSession assertGlobalSessionNotNull(String xid, boolean withBranchSessions)
            throws TransactionException {
        GlobalSession globalSession = SessionHolder.findGlobalSession(xid, withBranchSessions);
        if (globalSession == null) {
            throw new GlobalTransactionException(TransactionExceptionCode.GlobalTransactionNotExist,
                    String.format("Could not found global transaction xid = %s, may be has finished.", xid));
        }
        return globalSession;
    }

    @Override
    public void branchReport(BranchType branchType, String xid, long branchId, BranchStatus status,
                             String applicationData) throws TransactionException {
        GlobalSession globalSession = assertGlobalSessionNotNull(xid, true);
        BranchSession branchSession = globalSession.getBranch(branchId);
        if (branchSession == null) {
            throw new BranchTransactionException(BranchTransactionNotExist,
                    String.format("Could not found branch session xid = %s branchId = %s", xid, branchId));
        }
        branchSession.setApplicationData(applicationData);
        globalSession.changeBranchStatus(branchSession, status);

        if (LOGGER.isInfoEnabled()) {
            LOGGER.info("Report branch status successfully, xid = {}, branchId = {}", globalSession.getXid(),
                branchSession.getBranchId());
        }
    }

    @Override
    public boolean lockQuery(BranchType branchType, String resourceId, String xid, String lockKeys)
            throws TransactionException {
        return true;
    }

    @Override
    public BranchStatus branchCommit(GlobalSession globalSession, BranchSession branchSession) throws TransactionException {
        try {
            BranchCommitRequest request = new BranchCommitRequest();
            request.setXid(branchSession.getXid());
            request.setBranchId(branchSession.getBranchId());
            request.setResourceId(branchSession.getResourceId());
            request.setApplicationData(branchSession.getApplicationData());
            request.setBranchType(branchSession.getBranchType());
            return branchCommitSend(request, globalSession, branchSession);
        } catch (IOException | TimeoutException e) {
            throw new BranchTransactionException(FailedToSendBranchCommitRequest,
                    String.format("Send branch commit failed, xid = %s branchId = %s", branchSession.getXid(),
                            branchSession.getBranchId()), e);
        }
    }

    protected BranchStatus branchCommitSend(BranchCommitRequest request, GlobalSession globalSession,
                                            BranchSession branchSession) throws IOException, TimeoutException {

        BranchCommitResponse response = (BranchCommitResponse) remotingServer.sendSyncRequest(
            branchSession.getResourceId(), branchSession.getClientId(), request, branchSession.isAT());
        return response.getBranchStatus();
    }

    @Override
    public BranchStatus branchRollback(GlobalSession globalSession, BranchSession branchSession) throws TransactionException {
        try {
            BranchRollbackRequest request = new BranchRollbackRequest();
            request.setXid(branchSession.getXid());
            request.setBranchId(branchSession.getBranchId());
            request.setResourceId(branchSession.getResourceId());
            request.setApplicationData(branchSession.getApplicationData());
            request.setBranchType(branchSession.getBranchType());
            return branchRollbackSend(request, globalSession, branchSession);
        } catch (IOException | TimeoutException e) {
            throw new BranchTransactionException(FailedToSendBranchRollbackRequest,
                    String.format("Send branch rollback failed, xid = %s branchId = %s",
                            branchSession.getXid(), branchSession.getBranchId()), e);
        }
    }

    protected BranchStatus branchRollbackSend(BranchRollbackRequest request, GlobalSession globalSession,
                                              BranchSession branchSession) throws IOException, TimeoutException {

        BranchRollbackResponse response = (BranchRollbackResponse) remotingServer.sendSyncRequest(
            branchSession.getResourceId(), branchSession.getClientId(), request, branchSession.isAT());
        return response.getBranchStatus();
    }

    @Override
    public String begin(String applicationId, String transactionServiceGroup, String name, int timeout)
            throws TransactionException {
        return null;
    }

    @Override
    public GlobalStatus commit(String xid) throws TransactionException {
        return null;
    }

    @Override
    public boolean doGlobalCommit(GlobalSession globalSession, boolean retrying) throws TransactionException {
        return true;
    }

    @Override
    public GlobalStatus globalReport(String xid, GlobalStatus globalStatus) throws TransactionException {
        return null;
    }

    @Override
    public GlobalStatus rollback(String xid) throws TransactionException {
        return null;
    }

    @Override
    public boolean doGlobalRollback(GlobalSession globalSession, boolean retrying) throws TransactionException {
        return true;
    }

    @Override
    public GlobalStatus getStatus(String xid) throws TransactionException {
        return null;
    }

    @Override
    public void doGlobalReport(GlobalSession globalSession, String xid, GlobalStatus globalStatus) throws TransactionException {

    }

    @Override
    public Boolean doBranchDelete(GlobalSession globalSession, BranchSession branchSession) throws TransactionException {
        return true;
    }

    @Override
    public BranchStatus branchDelete(GlobalSession globalSession, BranchSession branchSession) throws TransactionException {
        return null;
    }
}
