/*
 *  Copyright 1999-2019 Seata.io Group.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package io.seata.server.raft.snapshot;

import java.io.Serializable;
import io.seata.common.util.StringUtils;
import io.seata.config.ConfigurationFactory;
import io.seata.core.compressor.CompressorType;
import io.seata.core.serializer.SerializerType;

import static io.seata.common.ConfigurationKeys.SERVER_RAFT_COMPRESSOR;
import static io.seata.common.ConfigurationKeys.SERVER_RAFT_SERIALIZATION;
import static io.seata.common.DefaultValues.DEFAULT_RAFT_COMPRESSOR;
import static io.seata.common.DefaultValues.DEFAULT_RAFT_SERIALIZATION;

/**
 * @author funkye
 */
public class RaftSnapshot implements Serializable {

    private byte codec = SerializerType
            .getByName(
                    ConfigurationFactory.getInstance().getConfig(SERVER_RAFT_SERIALIZATION, DEFAULT_RAFT_SERIALIZATION))
            .getCode();
    private byte compressor = CompressorType
            .getByName(ConfigurationFactory.getInstance().getConfig(SERVER_RAFT_COMPRESSOR, DEFAULT_RAFT_COMPRESSOR))
            .getCode();
    private Object body;

    /**
     * Gets body.
     *
     * @return the body
     */
    public Object getBody() {
        return body;
    }

    /**
     * Sets body.
     *
     * @param body the body
     */
    public void setBody(Object body) {
        this.body = body;
    }

    /**
     * Gets codec.
     *
     * @return the codec
     */
    public byte getCodec() {
        return codec;
    }

    /**
     * Sets codec.
     *
     * @param codec the codec
     * @return the codec
     */
    public RaftSnapshot setCodec(byte codec) {
        this.codec = codec;
        return this;
    }

    /**
     * Gets compressor.
     *
     * @return the compressor
     */
    public byte getCompressor() {
        return compressor;
    }

    /**
     * Sets compressor.
     *
     * @param compressor the compressor
     * @return the compressor
     */
    public RaftSnapshot setCompressor(byte compressor) {
        this.compressor = compressor;
        return this;
    }


    @Override
    public String toString() {
        return StringUtils.toString(this);
    }

}
