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
package org.apache.seata.rm.datasource.undo;

import org.apache.seata.rm.datasource.SqlGenerateUtils;
import org.apache.seata.rm.datasource.undo.SQLUndoLog;
import org.apache.seata.sqlparser.SQLType;
import org.apache.seata.rm.datasource.sql.struct.Field;
import org.apache.seata.rm.datasource.sql.struct.Row;
import org.apache.seata.sqlparser.struct.TableMeta;
import org.apache.seata.rm.datasource.sql.struct.TableRecords;
import org.apache.seata.sqlparser.util.JdbcConstants;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.sql.SQLException;
import java.util.*;


public class AbstractUndoExecutorTest extends BaseH2Test {

    @Test
    public void dataValidationUpdate() throws SQLException {
        execSQL("INSERT INTO table_name(id, name) VALUES (12345,'aaa');");
        execSQL("INSERT INTO table_name(id, name) VALUES (12346,'aaa');");

        TableRecords beforeImage = execQuery(tableMeta, "SELECT * FROM table_name WHERE id IN (12345, 12346);");

        execSQL("update table_name set name = 'xxx' where id in (12345, 12346);");

        TableRecords afterImage = execQuery(tableMeta, "SELECT * FROM table_name WHERE id IN (12345, 12346);");

        SQLUndoLog sqlUndoLog = new SQLUndoLog();
        sqlUndoLog.setSqlType(SQLType.UPDATE);
        sqlUndoLog.setTableMeta(tableMeta);
        sqlUndoLog.setTableName("table_name");
        sqlUndoLog.setBeforeImage(beforeImage);
        sqlUndoLog.setAfterImage(afterImage);

        TestUndoExecutor spy = new TestUndoExecutor(sqlUndoLog, false);

        // case1: normal case  before:aaa -> after:xxx -> current:xxx
        Assertions.assertTrue(spy.dataValidationAndGoOn(connection));

        // case2: dirty data   before:aaa -> after:xxx -> current:yyy
        execSQL("update table_name set name = 'yyy' where id in (12345, 12346);");
        try {
            spy.dataValidationAndGoOn(connection);
            Assertions.fail();
        } catch (Exception e) {
            Assertions.assertTrue(e instanceof SQLException);
        }

        // case 3: before == current before:aaa -> after:xxx -> current:aaa
        execSQL("update table_name set name = 'aaa' where id in (12345, 12346);");
        Assertions.assertFalse(spy.dataValidationAndGoOn(connection));

        // case 4: before == after   before:aaa -> after:aaa
        afterImage = execQuery(tableMeta, "SELECT * FROM table_name WHERE id IN (12345, 12346);");
        sqlUndoLog.setAfterImage(afterImage);
        Assertions.assertFalse(spy.dataValidationAndGoOn(connection));
    }

    @Test
    public void dataValidationInsert() throws SQLException {
        TableRecords beforeImage = execQuery(tableMeta, "SELECT * FROM table_name WHERE id IN (12345, 12346);");

        execSQL("INSERT INTO table_name(id, name) VALUES (12345,'aaa');");
        execSQL("INSERT INTO table_name(id, name) VALUES (12346,'aaa');");

        TableRecords afterImage = execQuery(tableMeta, "SELECT * FROM table_name WHERE id IN (12345, 12346);");

        SQLUndoLog sqlUndoLog = new SQLUndoLog();
        sqlUndoLog.setSqlType(SQLType.INSERT);
        sqlUndoLog.setTableMeta(tableMeta);
        sqlUndoLog.setTableName("table_name");
        sqlUndoLog.setBeforeImage(beforeImage);
        sqlUndoLog.setAfterImage(afterImage);

        TestUndoExecutor spy = new TestUndoExecutor(sqlUndoLog, false);

        // case1: normal case  before:0 -> after:2 -> current:2 
        Assertions.assertTrue(spy.dataValidationAndGoOn(connection));

        // case2: dirty data   before:0 -> after:2 -> current:2' 
        execSQL("update table_name set name = 'yyy' where id in (12345, 12346);");
        try {
            Assertions.assertTrue(spy.dataValidationAndGoOn(connection));
            Assertions.fail();
        } catch (Exception e) {
            Assertions.assertTrue(e instanceof SQLException);
        }

        // case3: before == current   before:0 -> after:2 -> current:0
        execSQL("delete from table_name where id in (12345, 12346);");
        Assertions.assertFalse(spy.dataValidationAndGoOn(connection));

        // case 4: before == after   before:0 -> after:0
        afterImage = execQuery(tableMeta, "SELECT * FROM table_name WHERE id IN (12345, 12346);");
        sqlUndoLog.setAfterImage(afterImage);
        Assertions.assertFalse(spy.dataValidationAndGoOn(connection));
    }

    @Test
    public void dataValidationDelete() throws SQLException {
        execSQL("INSERT INTO table_name(id, name) VALUES (12345,'aaa');");
        execSQL("INSERT INTO table_name(id, name) VALUES (12346,'aaa');");

        TableRecords beforeImage = execQuery(tableMeta, "SELECT * FROM table_name WHERE id IN (12345, 12346);");

        execSQL("delete from table_name where id in (12345, 12346);");

        TableRecords afterImage = execQuery(tableMeta, "SELECT * FROM table_name WHERE id IN (12345, 12346);");

        SQLUndoLog sqlUndoLog = new SQLUndoLog();
        sqlUndoLog.setSqlType(SQLType.INSERT);
        sqlUndoLog.setTableMeta(tableMeta);
        sqlUndoLog.setTableName("table_name");
        sqlUndoLog.setBeforeImage(beforeImage);
        sqlUndoLog.setAfterImage(afterImage);

        TestUndoExecutor spy = new TestUndoExecutor(sqlUndoLog, true);

        // case1: normal case  before:2 -> after:0 -> current:0
        Assertions.assertTrue(spy.dataValidationAndGoOn(connection));

        // case2: dirty data   before:2 -> after:0 -> current:1
        execSQL("INSERT INTO table_name(id, name) VALUES (12345,'aaa');");
        try {
            Assertions.assertTrue(spy.dataValidationAndGoOn(connection));
            Assertions.fail();
        } catch (Exception e) {
            Assertions.assertTrue(e instanceof SQLException);
        }

        // case3: before == current   before:2 -> after:0 -> current:2
        execSQL("INSERT INTO table_name(id, name) VALUES (12346,'aaa');");
        Assertions.assertFalse(spy.dataValidationAndGoOn(connection));

        // case 4: before == after  before:2 -> after:2
        afterImage = execQuery(tableMeta, "SELECT * FROM table_name WHERE id IN (12345, 12346);");
        sqlUndoLog.setAfterImage(afterImage);
        Assertions.assertFalse(spy.dataValidationAndGoOn(connection));
    }

    @Test
    public void testParsePK() {
        TableMeta tableMeta = Mockito.mock(TableMeta.class);
        Mockito.when(tableMeta.getPrimaryKeyOnlyName()).thenReturn(Collections.singletonList("id"));
        Mockito.when(tableMeta.getTableName()).thenReturn("table_name");

        TableRecords beforeImage = new TableRecords();
        beforeImage.setTableName("table_name");
        beforeImage.setTableMeta(tableMeta);

        List<Row> beforeRows = new ArrayList<>();
        Row row0 = new Row();
        addField(row0, "id", 1, "12345");
        addField(row0, "age", 1, "2");
        beforeRows.add(row0);
        Row row1 = new Row();
        addField(row1, "id", 1, "12346");
        addField(row1, "age", 1, "2");
        beforeRows.add(row1);
        beforeImage.setRows(beforeRows);

        SQLUndoLog sqlUndoLog = new SQLUndoLog();
        sqlUndoLog.setSqlType(SQLType.UPDATE);
        sqlUndoLog.setTableMeta(tableMeta);
        sqlUndoLog.setTableName("table_name");
        sqlUndoLog.setBeforeImage(beforeImage);
        sqlUndoLog.setAfterImage(null);

        TestUndoExecutor executor = new TestUndoExecutor(sqlUndoLog, true);
        Map<String,List<Field>> pkValues = executor.parsePkValues(beforeImage);
        Assertions.assertEquals(2, pkValues.get("id").size());
    }

    @Test
    public void testBuildWhereConditionByPKs() throws SQLException {
        List<String> pkNameList =new ArrayList<>();
        pkNameList.add("id1");
        pkNameList.add("id2");

        Map<String, List<Field>> pkRowValues = new HashMap<>();
        List<Field> pkId1Values = new ArrayList<>();
        pkId1Values.add(new Field());
        pkId1Values.add(new Field());
        pkId1Values.add(new Field());
        List<Field> pkId2Values = new ArrayList<>();
        pkId2Values.add(new Field());
        pkId2Values.add(new Field());
        pkId2Values.add(new Field());
        pkRowValues.put("id1", pkId1Values);
        pkRowValues.put("id2", pkId2Values);

        List<SqlGenerateUtils.WhereSql> sql = SqlGenerateUtils.buildWhereConditionListByPKs(pkNameList, pkRowValues.get("id1").size(), JdbcConstants.MYSQL, 1000);
        Assertions.assertEquals("(id1,id2) in ( (?,?),(?,?),(?,?) )", sql.get(0).getSql());
        sql = SqlGenerateUtils.buildWhereConditionListByPKs(pkNameList, pkRowValues.get("id1").size(), JdbcConstants.MARIADB, 1000);
        Assertions.assertEquals("(id1,id2) in ( (?,?),(?,?),(?,?) )", sql.get(0).getSql());
        sql = SqlGenerateUtils.buildWhereConditionListByPKs(pkNameList, pkRowValues.get("id1").size(), JdbcConstants.POLARDBX, 1000);
        Assertions.assertEquals("(id1,id2) in ( (?,?),(?,?),(?,?) )", sql.get(0).getSql());
    }

    @Test
    public void testBuildWhereConditionByPK() throws SQLException {
        List<String> pkNameList = new ArrayList<>();
        pkNameList.add("id1");

        Map<String, List<Field>> pkRowValues = new HashMap<>();
        List<Field> pkId1Values = new ArrayList<>();
        pkId1Values.add(new Field());
        pkRowValues.put("id1", pkId1Values);

        List<SqlGenerateUtils.WhereSql> sql = SqlGenerateUtils.buildWhereConditionListByPKs(pkNameList, pkRowValues.get("id1").size(), JdbcConstants.MYSQL);
        Assertions.assertEquals("(id1) in ( (?) )", sql.get(0).getSql());
        sql = SqlGenerateUtils.buildWhereConditionListByPKs(pkNameList, pkRowValues.get("id1").size(), JdbcConstants.MARIADB);
        Assertions.assertEquals("(id1) in ( (?) )", sql.get(0).getSql());
        sql = SqlGenerateUtils.buildWhereConditionListByPKs(pkNameList, pkRowValues.get("id1").size(), JdbcConstants.POLARDBX);
        Assertions.assertEquals("(id1) in ( (?) )", sql.get(0).getSql());
    }
}

class TestUndoExecutor extends AbstractUndoExecutor {
    private final boolean isDelete;
    public TestUndoExecutor(SQLUndoLog sqlUndoLog, boolean isDelete) {
        super(sqlUndoLog);
        this.isDelete = isDelete;
    }

    @Override
    protected String buildUndoSQL() {
        return null;
    }

    @Override
    protected TableRecords getUndoRows() {
        return isDelete ? sqlUndoLog.getBeforeImage() : sqlUndoLog.getAfterImage();
    }
}
