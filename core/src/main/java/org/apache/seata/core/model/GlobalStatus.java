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
package org.apache.seata.core.model;

/**
 * Status of global transaction.
 *
 */
public enum GlobalStatus {

    /**
     * Un known global status.
     */
    // Unknown
    UnKnown(0, "an ambiguous transaction state, usually use before begin"),

    /**
     * The Begin.
     */
    // PHASE 1: can accept new branch registering.
    Begin(1, "global transaction start"),

    /**
     * PHASE 2: Running Status: may be changed any time.
     */
    // Committing.
    Committing(2, "2Phase committing"),

    /**
     * The Commit retrying.
     */
    // Retrying commit after a recoverable failure.
    CommitRetrying(3, "2Phase committing failure retry"),

    /**
     * Rollbacking global status.
     */
    // Rollbacking
    Rollbacking(4, "2Phase rollbacking"),

    /**
     * The Rollback retrying.
     */
    // Retrying rollback after a recoverable failure.
    RollbackRetrying(5, "2Phase rollbacking failure retry"),

    /**
     * The Timeout rollbacking.
     */
    // Rollbacking since timeout
    TimeoutRollbacking(6, "after global transaction timeout rollbacking"),

    /**
     * The Timeout rollback retrying.
     */
    // Retrying rollback (since timeout) after a recoverable failure.
    TimeoutRollbackRetrying(7, "after global transaction timeout rollback retrying"),

    /**
     * All branches can be async committed. The committing is NOT done yet, but it can be seen as committed for TM/RM
     * client.
     */
    AsyncCommitting(8, "2Phase committing, used for AT mode"),

    /**
     * PHASE 2: Final Status: will NOT change any more.
     */
    // Finally: global transaction is successfully committed.
    Committed(9, "global transaction completed with status committed"),

    /**
     * The Commit failed.
     */
    // Finally: failed to commit
    CommitFailed(10, "2Phase commit failed"),

    /**
     * The Rollbacked.
     */
    // Finally: global transaction is successfully rollbacked.
    Rollbacked(11, "global transaction completed with status rollbacked"),

    /**
     * The Rollback failed.
     */
    // Finally: failed to rollback
    RollbackFailed(12, "global transaction completed but rollback failed"),

    /**
     * The Timeout rollbacked.
     */
    // Finally: global transaction is successfully rollbacked since timeout.
    TimeoutRollbacked(13, "global transaction completed with rollback due to timeout"),

    /**
     * The Timeout rollback failed.
     */
    // Finally: failed to rollback since timeout
    TimeoutRollbackFailed(14, "global transaction was rollbacking due to timeout, but failed"),

    /**
     * The Finished.
     */
    // Not managed in session MAP any more
    Finished(15, "ambiguous transaction status for non-exist transaction and global report for Saga"),

    /**
     * The commit retry Timeout .
     */
    // Finally: failed to commit since retry timeout
    CommitRetryTimeout(16, "global transaction still failed after commit failure and retries for some time"),

    /**
     * The rollback retry Timeout .
     */
    // Finally: failed to rollback since retry timeout
    RollbackRetryTimeout(17, "global transaction still failed after commit failure and retries for some time"),

    /**
     * Deleting .
     */
    // Deleting global transaction
    Deleting(18, "global transaction is deleting"),

    /**
     * Stop commit or commit retry .
     */
    // stop commit or commit retry
    StopCommitOrCommitRetry(19,"global transaction is commit or retry commit but stop now"),

    /**
     * Stop rollback or rollback retry .
     */
    // stop rollback or rollback retry
    StopRollbackOrRollbackRetry(20,"global transaction is rollback or retry rollback but stop now");

    private final int code;
    private final String desc;

    GlobalStatus(int code, String desc) {
        this.code = code;
        this.desc = desc;
    }

    /**
     * Gets code.
     *
     * @return the code
     */
    public int getCode() {
        return code;
    }

    /**
     * Get global status.
     *
     * @param code the code
     * @return the global status
     */
    public static GlobalStatus get(byte code) {
        return get((int)code);
    }

    /**
     * Get global status.
     *
     * @param code the code
     * @return the global status
     */
    public static GlobalStatus get(int code) {
        GlobalStatus value = null;
        try {
            value = GlobalStatus.values()[code];
        } catch (Exception e) {
            throw new IllegalArgumentException("Unknown GlobalStatus[" + code + "]");
        }
        return value;
    }

    /**
     * Is one phase timeout boolean.
     *
     * @param status the status
     * @return the boolean
     */
    public static boolean isOnePhaseTimeout(GlobalStatus status) {
        if (status == TimeoutRollbacking || status == TimeoutRollbackRetrying || status == TimeoutRollbacked || status == TimeoutRollbackFailed) {
            return true;
        }
        return false;
    }

    /**
     * Is two phase success boolean.
     *
     * @param status the status
     * @return the boolean
     */
    public static boolean isTwoPhaseSuccess(GlobalStatus status) {
        if (status == GlobalStatus.Committed || status == GlobalStatus.Rollbacked
            || status == GlobalStatus.TimeoutRollbacked || status == GlobalStatus.Deleting) {
            return true;
        }
        return false;
    }

    /**
     * Is two phase heuristic boolean.
     *
     * @param status the status
     * @return the boolean
     */
    public static boolean isTwoPhaseHeuristic(GlobalStatus status) {
        if (status == GlobalStatus.Finished) {
            return true;
        }
        return false;
    }
}
