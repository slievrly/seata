-- adapted for h2 versions 2.x and above.
CREATE TABLE IF NOT EXISTS seata_state_machine_def (
   id VARCHAR(32) NOT NULL COMMENT 'id',
   name VARCHAR(128) NOT NULL COMMENT 'name',
   tenant_id VARCHAR(32) NOT NULL COMMENT 'tenant id',
   app_name VARCHAR(32) NOT NULL COMMENT 'application name',
   type VARCHAR(20) COMMENT 'state language type',
   comment_ VARCHAR(255) COMMENT 'comment',
   ver VARCHAR(16) NOT NULL COMMENT 'version',
   gmt_create TIMESTAMP(3) NOT NULL COMMENT 'create time',
   status VARCHAR(2) NOT NULL COMMENT 'status(AC:active|IN:inactive)',
   content CLOB COMMENT 'content',
   recover_strategy VARCHAR(16) COMMENT 'transaction recover strategy(compensate|retry)',
   PRIMARY KEY (id)
);

CREATE TABLE IF NOT EXISTS seata_state_machine_inst (
    ID VARCHAR (128) NOT NULL COMMENT 'id',
    machine_id VARCHAR (32) NOT NULL COMMENT 'state machine definition id',
    tenant_id VARCHAR (32) NOT NULL COMMENT 'tenant id',
    parent_id VARCHAR (128) COMMENT 'parent id',
    gmt_started TIMESTAMP (3) NOT NULL COMMENT 'start time',
    business_key VARCHAR (48) COMMENT 'business key',
    start_params CLOB COMMENT 'start parameters',
    gmt_end TIMESTAMP (3) COMMENT 'end time',
    excep BLOB COMMENT 'exception',
    end_params CLOB COMMENT 'end parameters',
    status VARCHAR (2) COMMENT 'status(SU succeed|FA failed|UN unknown|SK skipped|RU running)',
    compensation_status VARCHAR (2) COMMENT 'compensation status(SU succeed|FA failed|UN unknown|SK skipped|RU running)',
    is_running TINYINT COMMENT 'is running(0 no|1 yes)',
    gmt_updated TIMESTAMP (3) NOT NULL,
    PRIMARY KEY (ID)
    );

ALTER TABLE seata_state_machine_inst ADD CONSTRAINT unikey_buz_tenant UNIQUE (business_key, tenant_id);


CREATE TABLE IF NOT EXISTS seata_state_inst (
    id VARCHAR(48) NOT NULL COMMENT 'id',
    machine_inst_id VARCHAR(128) NOT NULL COMMENT 'state machine instance id',
    name VARCHAR(128) NOT NULL COMMENT 'state name',
    type VARCHAR(20) COMMENT 'state type',
    service_name VARCHAR(128) COMMENT 'service name',
    service_method VARCHAR(128) COMMENT 'method name',
    service_type VARCHAR(16) COMMENT 'service type',
    business_key VARCHAR(48) COMMENT 'business key',
    state_id_compensated_for VARCHAR(50) COMMENT 'state compensated for',
    state_id_retried_for VARCHAR(50) COMMENT 'state retried for',
    gmt_started TIMESTAMP(3) NOT NULL COMMENT 'start time',
    is_for_update TINYINT COMMENT 'is service for update',
    input_params CLOB COMMENT 'input parameters',
    output_params CLOB COMMENT 'output parameters',
    status VARCHAR(2) NOT NULL COMMENT 'status(SU succeed|FA failed|UN unknown|SK skipped|RU running)',
    excep BLOB COMMENT 'exception',
    gmt_updated TIMESTAMP(3) COMMENT 'update time',
    gmt_end TIMESTAMP(3) COMMENT 'end time',
    PRIMARY KEY (id, machine_inst_id)
);