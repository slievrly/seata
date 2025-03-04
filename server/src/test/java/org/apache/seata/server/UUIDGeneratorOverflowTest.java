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
package org.apache.seata.server;

import org.apache.seata.common.util.UUIDGenerator;
import org.junit.jupiter.api.Test;

/**
 * The type Uuid generator overflow test.
 */
public class UUIDGeneratorOverflowTest {
    private static final int UUID_GENERATE_COUNT = 5;
    private static final Long SERVER_NODE_ID = 1023L;

    /**
     * Test generate uuid.
     */
    @Test
    public void testGenerateUUID() {
        UUIDGenerator.init(SERVER_NODE_ID);
        for (int i = 0; i < UUID_GENERATE_COUNT; i++) {
            System.out.println("[UUID " + i + "] is: " + UUIDGenerator.generateUUID());
        }
    }
}
