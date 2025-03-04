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
package org.apache.seata.saga.engine.pcext.interceptors;

import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.apache.seata.common.exception.FrameworkErrorCode;
import org.apache.seata.common.loader.LoadLevel;
import org.apache.seata.common.util.CollectionUtils;
import org.apache.seata.common.util.StringUtils;
import org.apache.seata.saga.engine.StateMachineConfig;
import org.apache.seata.saga.engine.exception.EngineExecutionException;
import org.apache.seata.saga.engine.expression.ELExpression;
import org.apache.seata.saga.engine.expression.Expression;
import org.apache.seata.saga.engine.expression.ExpressionResolver;
import org.apache.seata.saga.engine.expression.exception.ExceptionMatchExpression;
import org.apache.seata.saga.engine.pcext.InterceptableStateHandler;
import org.apache.seata.saga.engine.pcext.StateHandlerInterceptor;
import org.apache.seata.saga.engine.pcext.StateInstruction;
import org.apache.seata.saga.engine.pcext.handlers.ServiceTaskStateHandler;
import org.apache.seata.saga.engine.pcext.handlers.SubStateMachineHandler;
import org.apache.seata.saga.engine.pcext.utils.CompensationHolder;
import org.apache.seata.saga.engine.pcext.utils.EngineUtils;
import org.apache.seata.saga.engine.pcext.utils.LoopTaskUtils;
import org.apache.seata.saga.engine.pcext.utils.ParameterUtils;
import org.apache.seata.saga.engine.utils.ExceptionUtils;
import org.apache.seata.saga.proctrl.HierarchicalProcessContext;
import org.apache.seata.saga.proctrl.ProcessContext;
import org.apache.seata.saga.statelang.domain.DomainConstants;
import org.apache.seata.saga.statelang.domain.ExecutionStatus;
import org.apache.seata.saga.statelang.domain.StateInstance;
import org.apache.seata.saga.statelang.domain.StateMachineInstance;
import org.apache.seata.saga.statelang.domain.impl.ServiceTaskStateImpl;
import org.apache.seata.saga.statelang.domain.impl.StateInstanceImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * StateInterceptor for ServiceTask, SubStateMachine, CompensateState
 *
 */
@LoadLevel(name = "ServiceTask", order = 100)
public class ServiceTaskHandlerInterceptor implements StateHandlerInterceptor {

    private static final Logger LOGGER = LoggerFactory.getLogger(ServiceTaskHandlerInterceptor.class);

    @Override
    public boolean match(Class<? extends InterceptableStateHandler> clazz) {
        return clazz != null &&
                (ServiceTaskStateHandler.class.isAssignableFrom(clazz)
                || SubStateMachineHandler.class.isAssignableFrom(clazz));
    }

    @Override
    public void preProcess(ProcessContext context) throws EngineExecutionException {

        StateInstruction instruction = context.getInstruction(StateInstruction.class);

        StateMachineInstance stateMachineInstance = (StateMachineInstance)context.getVariable(
            DomainConstants.VAR_NAME_STATEMACHINE_INST);
        StateMachineConfig stateMachineConfig = (StateMachineConfig)context.getVariable(
            DomainConstants.VAR_NAME_STATEMACHINE_CONFIG);

        if (EngineUtils.isTimeout(stateMachineInstance.getGmtUpdated(), stateMachineConfig.getTransOperationTimeout())) {
            String message = "Saga Transaction [stateMachineInstanceId:" + stateMachineInstance.getId()
                    + "] has timed out, stop execution now.";

            LOGGER.error(message);

            EngineExecutionException exception = ExceptionUtils.createEngineExecutionException(null,
                    FrameworkErrorCode.StateMachineExecutionTimeout, message, stateMachineInstance, instruction.getStateName());

            EngineUtils.failStateMachine(context, exception);

            throw exception;
        }

        StateInstanceImpl stateInstance = new StateInstanceImpl();

        Map<String, Object> contextVariables = (Map<String, Object>)context.getVariable(
            DomainConstants.VAR_NAME_STATEMACHINE_CONTEXT);
        ServiceTaskStateImpl state = (ServiceTaskStateImpl)instruction.getState(context);
        List<Object> serviceInputParams = null;
        if (contextVariables != null) {
            try {
                serviceInputParams = ParameterUtils.createInputParams(stateMachineConfig.getExpressionResolver(), stateInstance,
                    state, contextVariables);
            } catch (Exception e) {

                String message = "Task [" + state.getName()
                    + "] input parameters assign failed, please check 'Input' expression:" + e.getMessage();

                EngineExecutionException exception = ExceptionUtils.createEngineExecutionException(e,
                    FrameworkErrorCode.VariablesAssignError, message, stateMachineInstance, state.getName());

                EngineUtils.failStateMachine(context, exception);

                throw exception;
            }
        }

        ((HierarchicalProcessContext)context).setVariableLocally(DomainConstants.VAR_NAME_INPUT_PARAMS,
            serviceInputParams);

        stateInstance.setMachineInstanceId(stateMachineInstance.getId());
        stateInstance.setStateMachineInstance(stateMachineInstance);
        boolean isForCompensation = state.isForCompensation();
        if (context.hasVariable(DomainConstants.VAR_NAME_IS_LOOP_STATE) && !isForCompensation) {
            stateInstance.setName(LoopTaskUtils.generateLoopStateName(context, state.getName()));
            StateInstance lastRetriedStateInstance = LoopTaskUtils.findOutLastRetriedStateInstance(stateMachineInstance,
                stateInstance.getName());
            stateInstance.setStateIdRetriedFor(
                lastRetriedStateInstance == null ? null : lastRetriedStateInstance.getId());
        } else {
            stateInstance.setName(state.getName());
            stateInstance.setStateIdRetriedFor(
                (String)context.getVariable(state.getName() + DomainConstants.VAR_NAME_RETRIED_STATE_INST_ID));
        }
        stateInstance.setGmtStarted(new Date());
        stateInstance.setGmtUpdated(stateInstance.getGmtStarted());
        stateInstance.setStatus(ExecutionStatus.RU);

        if (StringUtils.hasLength(stateInstance.getBusinessKey())) {

            ((Map<String, Object>)context.getVariable(DomainConstants.VAR_NAME_STATEMACHINE_CONTEXT)).put(
                state.getName() + DomainConstants.VAR_NAME_BUSINESSKEY, stateInstance.getBusinessKey());
        }

        stateInstance.setType(state.getType());

        stateInstance.setForUpdate(state.isForUpdate());
        stateInstance.setServiceName(state.getServiceName());
        stateInstance.setServiceMethod(state.getServiceMethod());
        stateInstance.setServiceType(state.getServiceType());

        if (isForCompensation) {
            CompensationHolder compensationHolder = CompensationHolder.getCurrent(context, true);
            StateInstance stateToBeCompensated = compensationHolder.getStatesNeedCompensation().get(state.getName());
            if (stateToBeCompensated != null) {

                stateToBeCompensated.setCompensationState(stateInstance);
                stateInstance.setStateIdCompensatedFor(stateToBeCompensated.getId());
            } else {
                LOGGER.error("Compensation State[{}] has no state to compensate, maybe this is a bug.",
                    state.getName());
            }
            CompensationHolder.getCurrent(context, true).addForCompensationState(stateInstance.getName(),
                stateInstance);
        }

        if (DomainConstants.OPERATION_NAME_FORWARD.equals(context.getVariable(DomainConstants.VAR_NAME_OPERATION_NAME))
            && StringUtils.isEmpty(stateInstance.getStateIdRetriedFor()) && !state.isForCompensation()) {

            List<StateInstance> stateList = stateMachineInstance.getStateList();
            if (CollectionUtils.isNotEmpty(stateList)) {
                for (int i = stateList.size() - 1; i >= 0; i--) {
                    StateInstance executedState = stateList.get(i);

                    if (stateInstance.getName().equals(executedState.getName())) {
                        stateInstance.setStateIdRetriedFor(executedState.getId());
                        executedState.setIgnoreStatus(true);
                        break;
                    }
                }
            }
        }

        stateInstance.setInputParams(serviceInputParams);

        if (stateMachineInstance.getStateMachine().isPersist() && state.isPersist()
            && stateMachineConfig.getStateLogStore() != null) {

            try {
                stateMachineConfig.getStateLogStore().recordStateStarted(stateInstance, context);
            } catch (Exception e) {

                String message = "Record state[" + state.getName() + "] started failed, stateMachineInstance[" + stateMachineInstance
                        .getId() + "], Reason: " + e.getMessage();

                EngineExecutionException exception = ExceptionUtils.createEngineExecutionException(e,
                        FrameworkErrorCode.ExceptionCaught, message, stateMachineInstance, state.getName());

                EngineUtils.failStateMachine(context, exception);

                throw exception;
            }
        }

        if (StringUtils.isEmpty(stateInstance.getId())) {
            stateInstance.setId(stateMachineConfig.getSeqGenerator().generate(DomainConstants.SEQ_ENTITY_STATE_INST));
        }
        stateMachineInstance.putStateInstance(stateInstance.getId(), stateInstance);
        ((HierarchicalProcessContext)context).setVariableLocally(DomainConstants.VAR_NAME_STATE_INST, stateInstance);
    }

    @Override
    public void postProcess(ProcessContext context, Exception exp) throws EngineExecutionException {

        StateInstruction instruction = context.getInstruction(StateInstruction.class);
        ServiceTaskStateImpl state = (ServiceTaskStateImpl)instruction.getState(context);

        StateMachineInstance stateMachineInstance = (StateMachineInstance)context.getVariable(
            DomainConstants.VAR_NAME_STATEMACHINE_INST);
        StateInstance stateInstance = (StateInstance)context.getVariable(DomainConstants.VAR_NAME_STATE_INST);
        if (stateInstance == null || !stateMachineInstance.isRunning()) {
            LOGGER.warn("StateMachineInstance[id:" + stateMachineInstance.getId() + "] is end. stop running");
            return;
        }

        StateMachineConfig stateMachineConfig = (StateMachineConfig)context.getVariable(
            DomainConstants.VAR_NAME_STATEMACHINE_CONFIG);

        if (exp == null) {
            exp = (Exception)context.getVariable(DomainConstants.VAR_NAME_CURRENT_EXCEPTION);
        }
        stateInstance.setException(exp);

        decideExecutionStatus(context, stateInstance, state, exp);

        if (ExecutionStatus.SU.equals(stateInstance.getStatus()) && exp != null) {

            if (LOGGER.isInfoEnabled()) {
                LOGGER.info(
                    "Although an exception occurs, the execution status map to SU, and the exception is ignored when "
                        + "the execution status decision.");
            }
            context.removeVariable(DomainConstants.VAR_NAME_CURRENT_EXCEPTION);
        }

        Map<String, Object> contextVariables = (Map<String, Object>)context.getVariable(
            DomainConstants.VAR_NAME_STATEMACHINE_CONTEXT);
        Object serviceOutputParams = context.getVariable(DomainConstants.VAR_NAME_OUTPUT_PARAMS);
        if (serviceOutputParams != null) {
            try {
                Map<String, Object> outputVariablesToContext = ParameterUtils.createOutputParams(
                    stateMachineConfig.getExpressionResolver(), state, serviceOutputParams);
                if (CollectionUtils.isNotEmpty(outputVariablesToContext)) {
                    contextVariables.putAll(outputVariablesToContext);
                }
            } catch (Exception e) {
                String message = "Task [" + state.getName()
                    + "] output parameters assign failed, please check 'Output' expression:" + e.getMessage();

                EngineExecutionException exception = ExceptionUtils.createEngineExecutionException(e,
                    FrameworkErrorCode.VariablesAssignError, message, stateMachineInstance, stateInstance);

                if (stateMachineInstance.getStateMachine().isPersist() && state.isPersist()
                    && stateMachineConfig.getStateLogStore() != null) {

                    stateInstance.setGmtEnd(new Date());
                    stateMachineConfig.getStateLogStore().recordStateFinished(stateInstance, context);
                }

                EngineUtils.failStateMachine(context, exception);

                throw exception;
            }
        }

        context.removeVariable(DomainConstants.VAR_NAME_OUTPUT_PARAMS);
        context.removeVariable(DomainConstants.VAR_NAME_INPUT_PARAMS);

        stateInstance.setGmtEnd(new Date());

        if (stateMachineInstance.getStateMachine().isPersist() && state.isPersist()
            && stateMachineConfig.getStateLogStore() != null) {
            stateMachineConfig.getStateLogStore().recordStateFinished(stateInstance, context);
        }

        if (exp != null && context.getVariable(DomainConstants.VAR_NAME_IS_EXCEPTION_NOT_CATCH) != null
            && (Boolean)context.getVariable(DomainConstants.VAR_NAME_IS_EXCEPTION_NOT_CATCH)) {
            //If there is an exception and there is no catch, need to exit the state machine to execute.

            context.removeVariable(DomainConstants.VAR_NAME_IS_EXCEPTION_NOT_CATCH);
            EngineUtils.failStateMachine(context, exp);
        }

    }

    private void decideExecutionStatus(ProcessContext context, StateInstance stateInstance, ServiceTaskStateImpl state,
                                       Exception exp) {
        Map<String, String> statusMatchList = state.getStatus();
        if (CollectionUtils.isNotEmpty(statusMatchList)) {
            if (state.isAsync()) {
                if (LOGGER.isWarnEnabled()) {
                    LOGGER.warn(
                        "Service[{}.{}] is execute asynchronously, null return value collected, so user defined "
                            + "Status Matching skipped. stateName: {}, branchId: {}", state.getServiceName(),
                        state.getServiceMethod(), state.getName(), stateInstance.getId());
                }
            } else {
                StateMachineConfig stateMachineConfig = (StateMachineConfig)context.getVariable(
                    DomainConstants.VAR_NAME_STATEMACHINE_CONFIG);
                ExpressionResolver resolver = stateMachineConfig.getExpressionResolver();

                Map<Object, String> statusEvaluators = state.getStatusEvaluators();
                if (statusEvaluators == null) {
                    synchronized (state) {
                        statusEvaluators = state.getStatusEvaluators();
                        if (statusEvaluators == null) {
                            statusEvaluators = new LinkedHashMap<>(statusMatchList.size());
                            String expressionStr, statusVal;
                            Expression evaluator;
                            for (Map.Entry<String, String> entry : statusMatchList.entrySet()) {
                                expressionStr = entry.getKey();
                                statusVal = entry.getValue();
                                evaluator = resolver.getExpression(expressionStr);
                                if (evaluator != null) {
                                    statusEvaluators.put(evaluator, statusVal);
                                }
                            }
                        }
                        state.setStatusEvaluators(statusEvaluators);
                    }
                }

                for (Object evaluatorObj : statusEvaluators.keySet()) {
                    Expression evaluator = (Expression) evaluatorObj;
                    String statusVal = statusEvaluators.get(evaluator);
                    Object elContext;

                    Class<? extends Expression> expressionClass = evaluator.getClass();
                    if (ExceptionMatchExpression.class.isAssignableFrom(expressionClass)) {
                        elContext = context.getVariable(DomainConstants.VAR_NAME_CURRENT_EXCEPTION);
                    } else if (ELExpression.class.isAssignableFrom(expressionClass)) {
                        elContext = context.getVariable(DomainConstants.VAR_NAME_OUTPUT_PARAMS);
                    } else {
                        elContext = context.getVariables();
                    }

                    if (Boolean.TRUE.equals(evaluator.getValue(elContext))) {
                        stateInstance.setStatus(ExecutionStatus.valueOf(statusVal));
                        break;
                    }
                }

                if (exp == null && (stateInstance.getStatus() == null || ExecutionStatus.RU.equals(
                    stateInstance.getStatus()))) {

                    if (state.isForUpdate()) {
                        stateInstance.setStatus(ExecutionStatus.UN);
                    } else {
                        stateInstance.setStatus(ExecutionStatus.FA);
                    }
                    stateInstance.setGmtEnd(new Date());

                    StateMachineInstance stateMachineInstance = stateInstance.getStateMachineInstance();

                    if (stateMachineInstance.getStateMachine().isPersist() && state.isPersist()
                        && stateMachineConfig.getStateLogStore() != null) {
                        stateMachineConfig.getStateLogStore().recordStateFinished(stateInstance, context);
                    }

                    EngineExecutionException exception = new EngineExecutionException("State [" + state.getName()
                        + "] execute finished, but cannot matching status, please check its status manually",
                        FrameworkErrorCode.NoMatchedStatus);
                    if (LOGGER.isDebugEnabled()) {
                        LOGGER.debug("State[{}] execute finish with status[{}]", state.getName(),
                            stateInstance.getStatus());
                    }
                    EngineUtils.failStateMachine(context, exception);

                    throw exception;
                }
            }
        }

        if (stateInstance.getStatus() == null || ExecutionStatus.RU.equals(stateInstance.getStatus())) {

            if (exp == null) {
                stateInstance.setStatus(ExecutionStatus.SU);
            } else {
                if (state.isForUpdate() || state.isForCompensation()) {

                    stateInstance.setStatus(ExecutionStatus.UN);
                    ExceptionUtils.NetExceptionType t = ExceptionUtils.getNetExceptionType(exp);
                    if (t != null) {
                        if (t.equals(ExceptionUtils.NetExceptionType.CONNECT_EXCEPTION)) {
                            stateInstance.setStatus(ExecutionStatus.FA);
                        } else if (t.equals(ExceptionUtils.NetExceptionType.READ_TIMEOUT_EXCEPTION)) {
                            stateInstance.setStatus(ExecutionStatus.UN);
                        }
                    } else {
                        stateInstance.setStatus(ExecutionStatus.UN);
                    }
                } else {
                    stateInstance.setStatus(ExecutionStatus.FA);
                }
            }
        }

        if (LOGGER.isInfoEnabled()) {
            LOGGER.info("State[{}] finish with status[{}]", state.getName(), stateInstance.getStatus());
        }
    }
}
