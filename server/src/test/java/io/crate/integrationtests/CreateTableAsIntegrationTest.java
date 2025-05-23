/*
 * Licensed to Crate.io GmbH ("Crate") under one or more contributor
 * license agreements.  See the NOTICE file distributed with this work for
 * additional information regarding copyright ownership.  Crate licenses
 * this file to you under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.  You may
 * obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations
 * under the License.
 *
 * However, if you have executed another commercial license agreement
 * with Crate these terms will supersede the license and you may use the
 * software solely pursuant to the terms of the relevant commercial agreement.
 */

package io.crate.integrationtests;

import static io.crate.testing.Asserts.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Map;

import org.elasticsearch.test.IntegTestCase;
import org.junit.Test;

import io.crate.exceptions.InvalidColumnNameException;
import io.crate.exceptions.RelationAlreadyExists;
import io.crate.exceptions.SQLParseException;
import io.crate.session.Session;
import io.crate.testing.UseJdbc;

public class CreateTableAsIntegrationTest extends IntegTestCase {

    /*
     * Testing re-creation of ColumnDefinitions is covered by SymbolToColumnDefinitionConverterTest
     * This is mainly for testing sanity and expected exceptions
     */

    @Test
    public void testCreateTableAsWithoutData() {
        execute("create table tbl ( col integer )");
        execute("create table cpy as select * from tbl");
        assertThat(response).hasRowCount(0);
    }

    @Test
    @SuppressWarnings("rawtypes")
    public void testCreateTableAsWithData() {
        String createTableStmt =
            "create table tbl (" +
            "   col_default_object object as (" +
            "       col_nested_integer integer," +
            "       col_nested_object object as (" +
            "           col_text text" +
            "       )" +
            "   )" +
            ")";
        execute(createTableStmt);
        execute("insert into tbl values({col_nested_integer=null,col_nested_object={col_text=null}})");
        execute("refresh table tbl");
        execute("create table cpy as select * from tbl");
        execute("refresh table cpy");
        execute("select * from cpy");

        assertThat(response).hasRowCount(1);
        assertThat(((Map) response.rows()[0][0]).get("col_nested_integer")).isNull();
        assertThat(((Map) ((Map) response.rows()[0][0]).get("col_nested_object")).get("col_text"))
            .isNull();
    }

    @Test
    @SuppressWarnings("rawtypes")
    public void testCreateTableAsParenthesesSyntax() throws Exception {
        String createTableStmt =
            "create table tbl (" +
            "   col_default_object object as (" +
            "       col_nested_integer integer," +
            "       col_nested_object object as (" +
            "           col_text text" +
            "       )" +
            "   )" +
            ")";
        execute(createTableStmt);
        execute("insert into tbl values({col_nested_integer=1,col_nested_object={col_text='test'}})");
        execute("refresh table tbl");
        execute("create table cpy as (select * from tbl)");
        execute("refresh table cpy");
        execute("select * from cpy");

        assertThat(response).hasRowCount(1);
        assertThat((int) ((Map) response.rows()[0][0]).get("col_nested_integer"))
            .isEqualTo(1);
        assertThat((String) ((Map) ((Map) response.rows()[0][0]).get("col_nested_object")).get("col_text"))
            .isEqualTo("test");
    }

    @UseJdbc(0)
    @Test
    public void testCreateTableAsColumnNamesInSubscriptNotation() {
        execute("create table tbl (col object(strict) as (nested_col text))");
        assertThatThrownBy(() -> execute("create table cpy as select col['nested_col'] from tbl"))
            .isExactlyInstanceOf(InvalidColumnNameException.class)
            .hasMessage("\"col['nested_col']\" conflicts with subscript pattern, square brackets are not allowed");
    }

    @UseJdbc(0)
    @Test
    public void testCreateTableAsDuplicateColumnNames() {
        execute("create table tbl (col_text text, col_int integer)");
        assertThatThrownBy(() -> execute("create table cpy as select col_text as col, col_int as col from tbl"))
            .isExactlyInstanceOf(SQLParseException.class)
            .hasMessage("column \"col\" specified more than once");
    }

    @UseJdbc(0)
    @Test
    public void testCreateTableAsExistingTableName() {
        execute("create table doc.tbl (col_text text, col_int integer)");
        execute("create table doc.cpy as select * from doc.tbl");
        assertThatThrownBy(() -> execute("create table doc.cpy as select * from doc.tbl"))
            .isExactlyInstanceOf(RelationAlreadyExists.class)
            .hasMessage("Relation 'doc.cpy' already exists.");
    }

    @Test
    public void testCreateTableIfNotExists() {
        execute("create table tbl (a int, b string)");
        execute("insert into tbl(a, b) select g, g || 'foo' from generate_series(1, 10, 1) as g");
        execute("refresh table tbl");
        execute("create table if not exists cpy as select * from tbl");
        assertThat(response).hasRowCount(10);
        execute("create table if not exists cpy as select * from tbl");
        assertThat(response).hasRowCount(0);
    }

    @Test
    public void test_subscript_on_expression_used_for_table_definition() {
        // Field exists
        execute("CREATE TABLE test_success AS \n" +
            "SELECT '{\"field1\":123}'::OBJECT (STRICT) AS (field1 BIGINT) ['field1']");
        assertThat(response).hasRowCount(1);

        // Fields does not exist
        // STRICT (error based on type definition)
        assertThatThrownBy(() -> execute("CREATE TABLE test_strict AS \n" +
            "SELECT '{\"field1\":123}'::OBJECT (STRICT) AS (field1 BIGINT) ['field2']"))
            .hasMessageContaining("The cast of `'{\"field1\":123}'` to return type `OBJECT(STRICT) AS (\"field1\" BIGINT)` does not contain the key `field2`.\n" +
                "Consider to include inner type definition in the `OBJECT` type while casting, disable DYNAMIC unknown key errors by the `error_on_unknown_object_key` setting or cast to `OBJECT(IGNORED)`.");

        // DYNAMIC (error based on type definition)
        assertThatThrownBy(() -> execute("CREATE TABLE test_dynamic AS \n" +
            "SELECT '{\"field1\":123}'::OBJECT (DYNAMIC) AS (field1 BIGINT) ['field2']"))
            .hasMessageContaining("The cast of `'{\"field1\":123}'` to return type `OBJECT(DYNAMIC) AS (\"field1\" BIGINT)` does not contain the key `field2`.\n" +
                "Consider to include inner type definition in the `OBJECT` type while casting, disable DYNAMIC unknown key errors by the `error_on_unknown_object_key` setting or cast to `OBJECT(IGNORED)`.");

        // IGNORED (error while using an undefined column as it cannot be stored)
        assertThatThrownBy(() -> execute("CREATE TABLE test_ignored AS \n" +
            "SELECT '{\"field1\":123}'::OBJECT (IGNORED) AS (field1 BIGINT) ['field2']"))
            .hasMessageContaining("Type `UNDEFINED` does not support storage");

        try (Session session = sqlExecutor.newSession()) {
            execute("SET SESSION error_on_unknown_object_key=false", session);

            // DYNAMIC (same as IGNORED, error while using an undefined column as it cannot be stored)
            assertThatThrownBy(() -> execute("CREATE TABLE test_dynamic AS \n" +
                "SELECT '{\"field1\":123}'::OBJECT (DYNAMIC) AS (field1 BIGINT) ['field2']", session))
                .hasMessageContaining("Type `UNDEFINED` does not support storage");
        }
    }
}
