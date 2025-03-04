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
package org.apache.seata.saga.annotation;

import org.apache.seata.rm.tcc.api.BusinessActionContextParameter;

/**
 * The type param.
 */
public class SagaParam {

    /**
     * The Num.
     */
    protected int num;

    /**
     * The Email.
     */
    @BusinessActionContextParameter(paramName = "email")
    protected String email;

    /**
     * Instantiates a new param.
     *
     * @param num   the num
     * @param email the email
     */
    public SagaParam(int num, String email) {
        this.num = num;
        this.email = email;
    }

    /**
     * Gets num.
     *
     * @return the num
     */
    public int getNum() {
        return num;
    }

    /**
     * Sets num.
     *
     * @param num the num
     */
    public void setNum(int num) {
        this.num = num;
    }
}