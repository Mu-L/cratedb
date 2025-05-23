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

package io.crate.analyze;

import static io.crate.testing.Asserts.assertList;
import static io.crate.testing.Asserts.assertThat;
import static io.crate.testing.Asserts.exactlyInstanceOf;
import static io.crate.testing.Asserts.isAlias;
import static io.crate.testing.Asserts.isDocTable;
import static io.crate.testing.Asserts.isField;
import static io.crate.testing.Asserts.isFunction;
import static io.crate.testing.Asserts.isLiteral;
import static io.crate.testing.Asserts.isReference;
import static io.crate.testing.Asserts.toCondition;
import static io.crate.types.ArrayType.makeArray;
import static org.assertj.core.api.Assertions.anyOf;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import org.assertj.core.api.Assertions;
import org.elasticsearch.Version;
import org.elasticsearch.common.io.stream.BytesStreamOutput;
import org.elasticsearch.common.io.stream.StreamInput;
import org.joda.time.Period;
import org.joda.time.PeriodType;
import org.junit.Test;

import io.crate.analyze.relations.AnalyzedRelation;
import io.crate.analyze.relations.DocTableRelation;
import io.crate.analyze.relations.TableFunctionRelation;
import io.crate.analyze.relations.TableRelation;
import io.crate.common.collections.Lists;
import io.crate.exceptions.AmbiguousColumnException;
import io.crate.exceptions.ColumnUnknownException;
import io.crate.exceptions.ConversionException;
import io.crate.exceptions.RelationUnknown;
import io.crate.exceptions.SchemaUnknownException;
import io.crate.exceptions.UnsupportedFeatureException;
import io.crate.exceptions.UnsupportedFunctionException;
import io.crate.execution.engine.aggregation.impl.average.AverageAggregation;
import io.crate.expression.eval.EvaluatingNormalizer;
import io.crate.expression.operator.EqOperator;
import io.crate.expression.operator.LikeOperators;
import io.crate.expression.operator.LteOperator;
import io.crate.expression.operator.OrOperator;
import io.crate.expression.operator.RegexpMatchOperator;
import io.crate.expression.operator.any.AnyEqOperator;
import io.crate.expression.predicate.IsNullPredicate;
import io.crate.expression.predicate.NotPredicate;
import io.crate.expression.scalar.SubscriptFunction;
import io.crate.expression.scalar.arithmetic.ArithmeticFunctions;
import io.crate.expression.scalar.cast.ExplicitCastFunction;
import io.crate.expression.scalar.cast.TryCastFunction;
import io.crate.expression.scalar.geo.DistanceFunction;
import io.crate.expression.symbol.AliasSymbol;
import io.crate.expression.symbol.Function;
import io.crate.expression.symbol.Literal;
import io.crate.expression.symbol.MatchPredicate;
import io.crate.expression.symbol.ParameterSymbol;
import io.crate.expression.symbol.SelectSymbol;
import io.crate.expression.symbol.Symbol;
import io.crate.expression.symbol.SymbolType;
import io.crate.expression.symbol.Symbols;
import io.crate.metadata.CoordinatorTxnCtx;
import io.crate.metadata.FunctionType;
import io.crate.metadata.PartitionName;
import io.crate.metadata.RelationName;
import io.crate.metadata.RowGranularity;
import io.crate.metadata.doc.DocTableInfo;
import io.crate.metadata.sys.SysNodesTableInfo;
import io.crate.sql.parser.ParsingException;
import io.crate.sql.tree.BitString;
import io.crate.sql.tree.ColumnPolicy;
import io.crate.test.integration.CrateDummyClusterServiceUnitTest;
import io.crate.testing.SQLExecutor;
import io.crate.testing.T3;
import io.crate.types.ArrayType;
import io.crate.types.DataType;
import io.crate.types.DataTypes;
import io.crate.types.ObjectType;
import io.crate.types.StringType;
import io.crate.types.TimeTZ;

@SuppressWarnings("ConstantConditions")
public class SelectStatementAnalyzerTest extends CrateDummyClusterServiceUnitTest {

    @Test
    public void testIsNullQuery() {
        var executor = SQLExecutor.of(clusterService);
        QueriedSelectRelation relation = executor.analyze("select * from sys.nodes where id is not null");
        Function query = (Function) relation.where();

        assertThat(query.name()).isEqualTo(NotPredicate.NAME);
        assertThat(query.arguments().getFirst()).isExactlyInstanceOf(Function.class);
        Function isNull = (Function) query.arguments().getFirst();
        assertThat(isNull.name()).isEqualTo(IsNullPredicate.NAME);
    }

    @Test
    public void testQueryUsesSearchPath() throws IOException {
        SQLExecutor executor = SQLExecutor.of(clusterService)
            .setSearchPath("first", "second", "third")
            .addTable("create table \"first\".t (id int)")
            .addTable("create table third.t1 (id int)");

        QueriedSelectRelation queriedTable = executor.analyze("select * from t");
        assertThat(queriedTable.from()).satisfiesExactly(isDocTable(new RelationName("first", "t")));

        queriedTable = executor.analyze("select * from t1");
        assertThat(queriedTable.from()).satisfiesExactly(isDocTable(new RelationName("third", "t1")));
    }

    @Test
    public void testOrderedSelect() throws Exception {
        var executor = SQLExecutor.of(clusterService);
        QueriedSelectRelation table = executor.analyze("select load['1'] from sys.nodes order by load['5'] desc");
        assertThat(table.limit()).isNull();

        assertThat(table.groupBy()).isEmpty();
        assertThat(table.orderBy()).isNotNull();

        assertThat(table.outputs()).hasSize(1);
        assertThat(table.orderBy().orderBySymbols()).hasSize(1);
        assertThat(table.orderBy().reverseFlags()).hasSize(1);

        assertThat(table.orderBy().orderBySymbols().getFirst()).isReference().hasName("load['5']");
    }

    @Test
    public void testNegativeLiteral() throws Exception {
        var executor = SQLExecutor.of(clusterService);
        QueriedSelectRelation relation = executor.analyze("select * from sys.nodes where port['http'] = -400");
        Function whereClause = (Function) relation.where();
        Symbol symbol = whereClause.arguments().get(1);
        assertThat(((Literal<?>) symbol).value()).isEqualTo(-400);
    }

    @Test
    public void testSimpleSelect() throws Exception {
        var executor = SQLExecutor.of(clusterService);
        QueriedSelectRelation relation = executor.analyze("select load['5'] from sys.nodes limit 2");
        assertThat(relation.limit()).isLiteral(2L);

        assertThat(relation.groupBy()).isEmpty();
        assertThat(relation.outputs()).hasSize(1);
        assertThat(relation.outputs().getFirst()).isReference().hasName("load['5']");
    }

    @Test
    public void testAggregationSelect() throws Exception {
        var executor = SQLExecutor.of(clusterService);
        QueriedSelectRelation relation = executor.analyze("select avg(load['5']) from sys.nodes");
        assertThat(relation.groupBy()).isEmpty();
        assertThat(relation.outputs()).hasSize(1);
        Function col1 = (Function) relation.outputs().getFirst();
        assertThat(col1.signature().getType()).isEqualTo(FunctionType.AGGREGATE);
        assertThat(col1.name()).isEqualTo(AverageAggregation.NAME);
    }

    private List<String> outputNames(AnalyzedRelation relation) {
        return Lists.map(relation.outputs(), x -> x.toColumn().sqlFqn());
    }

    @Test
    public void testAllColumnCluster() throws Exception {
        var executor = SQLExecutor.of(clusterService);
        AnalyzedRelation relation = executor.analyze("select * from sys.cluster");
        assertThat(relation.outputs()).hasSize(5);
        assertThat(outputNames(relation)).containsExactlyInAnyOrder("id", "license", "master_node", "name", "settings");
        assertThat(relation.outputs()).hasSize(5);
    }

    @Test
    public void testAllColumnNodes() throws Exception {
        var executor = SQLExecutor.of(clusterService);
        AnalyzedRelation relation = executor.analyze("select id, * from sys.nodes");
        List<String> outputNames = outputNames(relation);
        assertThat(outputNames).containsExactly(
            "id",
            "attributes",
            "cluster_state_version",
            "connections",
            "fs",
            "heap",
            "hostname",
            "id",
            "load",
            "mem",
            "name",
            "os",
            "os_info",
            "port",
            "process",
            "rest_url",
            "thread_pools",
            "version"
        );
        assertThat(relation.outputs()).hasSize(outputNames.size());
    }

    @Test
    public void testWhereSelect() throws Exception {
        var executor = SQLExecutor.of(clusterService);
        QueriedSelectRelation relation = executor.analyze(
            "select load from sys.nodes where load['1'] = 1.2 or 1 >= load['5']");

        assertThat(relation.groupBy()).isEmpty();

        Function whereClause = (Function) relation.where();
        assertThat(whereClause.name()).isEqualTo(OrOperator.NAME);
        assertThat(whereClause.signature().getType() == FunctionType.AGGREGATE).isFalse();

        Function left = (Function) whereClause.arguments().getFirst();
        assertThat(left.name()).isEqualTo(EqOperator.NAME);

        assertThat(left.arguments().getFirst()).isReference().hasName("load['1']");

        assertThat(left.arguments().get(1)).isExactlyInstanceOf(Literal.class);
        assertThat(left.arguments().get(1).valueType()).isEqualTo(DataTypes.DOUBLE);

        Function right = (Function) whereClause.arguments().get(1);
        assertThat(right.name()).isEqualTo(LteOperator.NAME);
        assertThat(right.arguments().getFirst()).isReference().hasName("load['5']");
        assertThat(right.arguments().get(1)).isExactlyInstanceOf(Literal.class);
        assertThat(left.arguments().get(1).valueType()).isEqualTo(DataTypes.DOUBLE);
    }

    @Test
    public void testSelectWithParameters() throws Exception {
        var executor = SQLExecutor.of(clusterService);
        QueriedSelectRelation relation = executor.analyze(
            "select load from sys.nodes " +
            "where load['1'] = ? or load['5'] <= ? or load['15'] >= ? or load['1'] = ? " +
            "or load['1'] = ? or name = ?");
        Function whereClause = (Function) relation.where();
        assertThat(whereClause.name()).isEqualTo(OrOperator.NAME);
        assertThat(whereClause.signature().getType() == FunctionType.AGGREGATE).isFalse();

        Function function = (Function) whereClause.arguments().getFirst();
        assertThat(function.name()).isEqualTo(OrOperator.NAME);
        function = (Function) function.arguments().get(1);
        assertThat(function.name()).isEqualTo(EqOperator.NAME);
        assertThat(function.arguments().get(1)).isExactlyInstanceOf(ParameterSymbol.class);
        assertThat(function.arguments().get(1).valueType()).isEqualTo(DataTypes.DOUBLE);

        function = (Function) whereClause.arguments().get(1);
        assertThat(function.name()).isEqualTo(EqOperator.NAME);
        assertThat(function.arguments().get(1)).isExactlyInstanceOf(ParameterSymbol.class);
        assertThat(function.arguments().get(1).valueType()).isEqualTo(DataTypes.STRING);
    }

    @Test
    public void testOutputNames() throws Exception {
        var executor = SQLExecutor.of(clusterService);
        AnalyzedRelation relation = executor.analyze("select load as l, id, load['1'] from sys.nodes");
        List<String> outputNames = outputNames(relation);
        assertThat(outputNames).containsExactly("l", "id", "load['1']");
    }

    @Test
    public void testDuplicateOutputNames() throws Exception {
        var executor = SQLExecutor.of(clusterService);
        AnalyzedRelation relation = executor.analyze("select load as l, load['1'] as l from sys.nodes");
        List<String> outputNames = outputNames(relation);
        assertThat(outputNames).containsExactly("l", "l");
    }

    @Test
    public void testOrderByOnAlias() throws Exception {
        var executor = SQLExecutor.of(clusterService);
        QueriedSelectRelation relation = executor.analyze(
            "select name as cluster_name from sys.cluster order by cluster_name");
        List<String> outputNames = outputNames(relation);
        assertThat(outputNames).hasSize(1);
        assertThat(outputNames.getFirst()).isEqualTo("cluster_name");

        assertThat(relation.orderBy()).isNotNull();
        assertThat(relation.orderBy().orderBySymbols()).hasSize(1);
        assertThat(relation.orderBy().orderBySymbols().getFirst()).isReference().hasName("name");
    }

    @Test
    public void testSelectGlobalAggregationOrderByWithColumnMissingFromSelect() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);

        assertThatThrownBy(() -> executor.analyze("select count(id) from users order by id"))
            .isExactlyInstanceOf(UnsupportedOperationException.class)
            .hasMessage("ORDER BY expression 'id' must appear in the select clause " +
                        "when grouping or global aggregation is used");
    }

    @Test
    public void testValidCombinationsOrderByWithAggregation() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);

        executor.analyze("select name, count(id) from users group by name order by 1");
        executor.analyze("select name, count(id) from users group by name order by 2");

        executor.analyze("select name, count(id) from users group by name order by name");
        executor.analyze("select name, count(id) from users group by name order by count(id)");

        executor.analyze("select name, count(id) from users group by name order by lower(name)");
        executor.analyze("select name, count(id) from users group by name order by lower(upper(name))");

        executor.analyze("select name, count(id) from users group by name order by sin(count(id))");
        executor.analyze("select name, count(id) from users group by name order by sin(sqrt(count(id)))");
    }

    @Test
    public void testLimitSupportInAnalyzer() throws Exception {
        var executor = SQLExecutor.of(clusterService);
        QueriedSelectRelation relation = executor.analyze("select * from sys.nodes limit 10");
        assertThat(relation.limit()).isLiteral(10L);
        relation = executor.analyze("select * from sys.nodes fetch first 10 rows only");
        assertThat(relation.limit()).isLiteral(10L);
        relation = executor.analyze("select * from sys.nodes fetch first '20'::long rows only");
        assertThat(relation.limit()).isLiteral(20L);
        relation = executor.analyze("select * from sys.nodes limit CAST(? AS int)");
        assertThat(relation.limit()).isExactlyInstanceOf(ParameterSymbol.class);
        assertThat(relation.limit()).hasDataType(DataTypes.LONG);
        relation = executor.analyze("select * from sys.nodes limit CAST(null AS int)");
        assertThat(relation.limit()).isLiteral(null);

        relation = executor.analyze("select * from sys.nodes limit all offset 3");
        assertThat(relation.limit()).isNull();
        assertThat(relation.offset()).isLiteral(3L);

        relation = executor.analyze("select * from sys.nodes limit all offset 0");
        assertThat(relation.limit()).isNull();
        assertThat(relation.offset()).isLiteral(0L);

        relation = executor.analyze("select * from sys.nodes limit null offset 3");
        assertThat(relation.limit()).isLiteral(null);
        assertThat(relation.offset()).isLiteral(3L);
        relation = executor.analyze("select * from sys.nodes fetch next null row only offset 3");
        assertThat(relation.limit()).isLiteral(null);
        assertThat(relation.offset()).isLiteral(3L);
    }

    @Test
    public void testOffsetSupportInAnalyzer() throws Exception {
        var executor = SQLExecutor.of(clusterService);
        QueriedSelectRelation relation = executor.analyze("select * from sys.nodes limit 1 offset 3");
        assertThat(relation.offset()).isLiteral(3L);
        relation = executor.analyze("select * from sys.nodes limit 1 offset 3 row");
        assertThat(relation.offset()).isLiteral(3L);
        relation = executor.analyze("select * from sys.nodes limit 1 offset 3 rows");
        assertThat(relation.offset()).isLiteral(3L);
        relation = executor.analyze("select * from sys.nodes limit 1 offset null");
        assertThat(relation.offset()).isLiteral(null);
        relation = executor.analyze("select * from sys.nodes offset '20'::long rows");
        assertThat(relation.offset()).isLiteral(20L);
        relation = executor.analyze("select * from sys.nodes offset CAST(? AS int)");
        assertThat(relation.offset()).isExactlyInstanceOf(ParameterSymbol.class);
        assertThat(relation.offset()).hasDataType(DataTypes.LONG);
        relation = executor.analyze("select * from sys.nodes offset CAST(null AS int)");
        assertThat(relation.offset()).isLiteral(null);
    }

    @Test
    public void testNoMatchStatement() throws Exception {
        var executor = SQLExecutor.of(clusterService);
        for (String stmt : List.of(
            "select id from sys.nodes where false",
            "select id from sys.nodes where 1=0"
        )) {
            QueriedSelectRelation relation = executor.analyze(stmt);
            assertThat(relation.where()).as(stmt).isLiteral(false);
        }
    }

    @Test
    public void testEvaluatingMatchAllStatement() throws Exception {
        var executor = SQLExecutor.of(clusterService);
        QueriedSelectRelation relation = executor.analyze("select id from sys.nodes where 1 = 1");
        assertThat(relation.where()).isLiteral(true);
    }

    @Test
    public void testAllMatchStatement() throws Exception {
        var executor = SQLExecutor.of(clusterService);
        for (String stmt : List.of(
            "select id from sys.nodes where true",
            "select id from sys.nodes where 1=1",
            "select id from sys.nodes"
        )) {
            QueriedSelectRelation relation = executor.analyze(stmt);
            assertThat(relation.where()).as(stmt).isLiteral(true);
        }
    }

    @Test
    public void testRewriteNotEquals() {
        var executor = SQLExecutor.of(clusterService);

        // should rewrite to:
        //    not(eq(sys.noes.name, 'something'))
        List<String> statements = List.of(
            "select * from sys.nodes where sys.nodes.name <> 'something'",
            "select * from sys.nodes where sys.nodes.name != 'something'"
        );
        for (String statement : statements) {
            QueriedSelectRelation relation = executor.analyze(statement);

            Function notFunction = (Function) relation.where();
            assertThat(notFunction.name()).isEqualTo(NotPredicate.NAME);
            assertThat(notFunction.arguments()).hasSize(1);

            Function eqFunction = (Function) notFunction.arguments().getFirst();
            assertThat(eqFunction.name()).isEqualTo(EqOperator.NAME);
            assertThat(eqFunction.arguments()).hasSize(2);

            List<Symbol> eqArguments = eqFunction.arguments();
            assertThat(eqArguments.get(1)).isLiteral("something");
        }
    }

    @Test
    public void testRewriteRegexpNoMatch() throws Exception {
        var executor = SQLExecutor.of(clusterService);
        String statement = "select * from sys.nodes where sys.nodes.name !~ '[sS]omething'";
        QueriedSelectRelation relation = executor.analyze(statement);

        Function notFunction = (Function) relation.where();
        assertThat(notFunction.name()).isEqualTo(NotPredicate.NAME);
        assertThat(notFunction.arguments()).hasSize(1);

        Function eqFunction = (Function) notFunction.arguments().getFirst();
        assertThat(eqFunction.name()).isEqualTo(RegexpMatchOperator.NAME);
        assertThat(eqFunction.arguments()).hasSize(2);

        List<Symbol> eqArguments = eqFunction.arguments();

        assertThat(eqArguments.getFirst()).isReference().hasName("name");
        assertThat(eqArguments.get(1)).isLiteral("[sS]omething");
    }

    @Test
    public void testGranularityWithSingleAggregation() throws Exception {
        var executor = SQLExecutor.of(clusterService);
        QueriedSelectRelation table = executor.analyze("select count(*) from sys.nodes");
        assertThat(((TableRelation) table.from().getFirst()).tableInfo().ident()).isEqualTo(SysNodesTableInfo.IDENT);
    }

    @Test
    public void testRewriteCountStringLiteral() {
        var executor = SQLExecutor.of(clusterService);
        AnalyzedRelation relation = executor.analyze("select count('id') from sys.nodes");
        List<Symbol> outputSymbols = relation.outputs();
        assertThat(outputSymbols).hasSize(1);
        assertThat(outputSymbols.getFirst()).isExactlyInstanceOf(Function.class);
        assertThat(((Function) outputSymbols.getFirst()).arguments()).isEmpty();
    }

    @Test
    public void testRewriteCountNull() {
        var executor = SQLExecutor.of(clusterService);
        AnalyzedRelation relation = executor.analyze("select count(null) from sys.nodes");
        List<Symbol> outputSymbols = relation.outputs();
        assertThat(outputSymbols).hasSize(1);
        assertThat(outputSymbols.getFirst()).isLiteral(0L);
    }

    @Test
    public void testWhereInSelect() throws Exception {
        var executor = SQLExecutor.of(clusterService);
        QueriedSelectRelation relation = executor.analyze(
            "select load from sys.nodes where load['1'] in (1.0, 2.0, 4.0, 8.0, 16.0)");
        Function whereClause = (Function) relation.where();
        assertThat(whereClause.name()).isEqualTo(AnyEqOperator.NAME);
    }

    @Test
    public void testWhereInSelectListWithNull() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        QueriedSelectRelation relation = executor.analyze("select 'found' from users where 1 in (3, 2, null)");
        assertThat(relation.where()).isLiteral(null);
    }

    @Test
    public void testWhereInSelectValueIsNull() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        QueriedSelectRelation relation = executor.analyze("select 'found' from users where null in (1, 2)");
        assertThat(relation.where()).isLiteral(null);
    }

    @Test
    public void testWhereInSelectDifferentDataTypeValue() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        QueriedSelectRelation relation;
        relation = executor.analyze("select 'found' from users where 1.2 in (1, 2)");
        assertThat(relation.where()).isLiteral(false); // already normalized to 1.2 in (1.0, 2.0) --> false
        relation = executor.analyze("select 'found' from users where 1 in (1.2, 2)");
        assertThat(relation.where()).isLiteral(false);
    }

    @Test
    public void testWhereInSelectDifferentDataTypeValueIncompatibleDataTypes() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);

        assertThatThrownBy(() -> executor.analyze("select 'found' from users where 1 in (1, 'foo', 2)"))
            .isExactlyInstanceOf(ConversionException.class)
            .hasMessage("Cannot cast `'foo'` of type `text` to type `integer`");
    }

    @Test
    public void testAggregationDistinct() {
        var executor = SQLExecutor.of(clusterService);
        AnalyzedRelation relation = executor.analyze("select count(distinct load['1']) from sys.nodes");

        Symbol output = relation.outputs().getFirst();
        assertThat(output).isFunction("collection_count");

        Function collectionCount = (Function) output;
        assertThat(collectionCount.arguments()).hasSize(1);
        Symbol symbol = collectionCount.arguments().getFirst();
        assertThat(symbol).isFunction("collect_set");

        Function collectSet = (Function) symbol;
        assertThat(collectSet.signature().getType()).isEqualTo(FunctionType.AGGREGATE);

        assertThat(collectSet.arguments()).hasSize(1);
        assertThat(collectSet.arguments().getFirst()).isReference().hasName("load['1']");
    }

    @Test
    public void test_count_distinct_on_length_limited_varchar_preserves_varchar_type() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable("create table tbl (name varchar(10))");

        Symbol symbol = executor.asSymbol("count(distinct name)");
        assertThat(symbol).isFunction("collection_count", List.of(new ArrayType<>(StringType.of(10))));
    }

    @Test
    public void testSelectDistinctWithFunction() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        QueriedSelectRelation relation = executor.analyze("select distinct id + 1 from users");
        assertThat(relation.isDistinct()).isTrue();
        assertList(relation.outputs()).isSQL("(doc.users.id + 1::bigint)");
    }

    @Test
    public void testSelectDistinctWithGroupBySameFieldsSameOrder() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        QueriedSelectRelation distinctRelation = executor.analyze("select distinct id, name from users group by id, name");
        QueriedSelectRelation groupByRelation = executor.analyze("select id, name from users group by id, name");
        assertThat(distinctRelation.groupBy()).isEqualTo(groupByRelation.groupBy());
        assertThat(distinctRelation.outputs()).isEqualTo(groupByRelation.outputs());
    }

    @Test
    public void testSelectDistinctWithGroupBySameFieldsDifferentOrder() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        AnalyzedRelation relation = executor.analyze("select distinct name, id from users group by id, name");
        assertThat(relation)
            .isSQL("SELECT doc.users.name, doc.users.id GROUP BY doc.users.id, doc.users.name");
    }

    @Test
    public void testDistinctOnLiteral() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        QueriedSelectRelation relation = executor.analyze("select distinct [1,2,3] from users");
        assertThat(relation.isDistinct()).isTrue();
        assertList(relation.outputs()).isSQL("[1, 2, 3]");
    }

    @Test
    public void testDistinctOnNullLiteral() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        QueriedSelectRelation relation = executor.analyze("select distinct null from users");
        assertThat(relation.isDistinct()).isTrue();
        assertList(relation.outputs()).isSQL("NULL");
    }

    @Test
    public void testSelectGlobalDistinctAggregate() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        QueriedSelectRelation relation = executor.analyze("select distinct count(*) from users");
        assertThat(relation.groupBy()).isEmpty();
    }

    @Test
    public void testSelectGlobalDistinctRewriteAggregationGroupBy() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        QueriedSelectRelation distinctRelation = executor.analyze("select distinct name, count(id) from users group by name");
        QueriedSelectRelation groupByRelation = executor.analyze("select name, count(id) from users group by name");
        assertThat(groupByRelation.groupBy()).isEqualTo(distinctRelation.groupBy());
    }

    @Test
    public void testSelectWithObjectLiteral() throws Exception {
        var executor = SQLExecutor.of(clusterService);
        QueriedSelectRelation relation = executor.analyze("select id from sys.nodes where load={\"1\"=1.0}");
        Function whereClause = (Function) relation.where();
        assertThat(whereClause.arguments())
            .satisfiesExactly(
                isReference("load"),
                isLiteral(Map.of("1", 1.0)));
    }

    @Test
    public void testLikeInWhereQuery() {
        var executor = SQLExecutor.of(clusterService);
        QueriedSelectRelation relation = executor.analyze("select * from sys.nodes where name like 'foo'");

        assertThat(relation.where()).isNotNull();
        Function whereClause = (Function) relation.where();
        assertThat(whereClause.name()).isEqualTo(LikeOperators.OP_LIKE);
        List<DataType<?>> argumentTypes = List.of(DataTypes.STRING, DataTypes.STRING);
        assertThat(argumentTypes).isEqualTo(Symbols.typeView(whereClause.arguments()));

        assertThat(whereClause.arguments().getFirst()).isReference().hasName("name");
        assertThat(whereClause.arguments().get(1)).isLiteral("foo");
    }

    @Test
    public void testILikeInWhereQuery() {
        var executor = SQLExecutor.of(clusterService);
        QueriedSelectRelation relation = executor.analyze("select * from sys.nodes where name ilike 'foo%'");

        assertThat(relation.where()).isNotNull();
        Function whereClause = (Function) relation.where();
        assertThat(whereClause.name()).isEqualTo(LikeOperators.OP_ILIKE);
        List<DataType<?>> argumentTypes = List.of(DataTypes.STRING, DataTypes.STRING);
        assertThat(argumentTypes).isEqualTo(Symbols.typeView(whereClause.arguments()));

        assertThat(whereClause.arguments().getFirst()).isReference().hasName("name");
        assertThat(whereClause.arguments().get(1)).isLiteral("foo%");
    }

    @Test
    public void testLikeNoStringDataTypeInWhereQuery() {
        var executor = SQLExecutor.of(clusterService);
        QueriedSelectRelation relation = executor.analyze("select * from sys.nodes where name like 1");

        // check if the implicit cast of the pattern worked
        List<DataType<?>> argumentTypes = List.of(DataTypes.STRING, DataTypes.STRING);
        Function whereClause = (Function) relation.where();
        assertThat(argumentTypes).isEqualTo(Symbols.typeView(whereClause.arguments()));
        assertThat(whereClause.arguments().get(1)).isExactlyInstanceOf(Literal.class);
        Literal<?> stringLiteral = (Literal<?>) whereClause.arguments().get(1);
        assertThat(stringLiteral.value()).isEqualTo("1");
    }

    @Test
    public void testLikeLongDataTypeInWhereQuery() {
        var executor = SQLExecutor.of(clusterService);
        QueriedSelectRelation relation = executor.analyze("select * from sys.nodes where 1 like 2");
        assertThat(relation.where()).isLiteral(false);
    }

    @Test
    public void testILikeLongDataTypeInWhereQuery() {
        var executor = SQLExecutor.of(clusterService);
        QueriedSelectRelation relation = executor.analyze("select * from sys.nodes where 1 ilike 2");
        assertThat(relation.where()).isLiteral(false);
    }

    @Test
    public void testIsNullInWhereQuery() {
        var executor = SQLExecutor.of(clusterService);
        QueriedSelectRelation relation = executor.analyze("select * from sys.nodes where name is null");
        Function isNullFunction = (Function) relation.where();

        assertThat(isNullFunction.name()).isEqualTo(IsNullPredicate.NAME);
        assertThat(isNullFunction.arguments()).hasSize(1);
        assertThat(isNullFunction.arguments().getFirst()).isReference().hasName("name");
        assertThat(relation.where()).isNotNull();
    }

    @Test
    public void testNullIsNullInWhereQuery() {
        var executor = SQLExecutor.of(clusterService);
        QueriedSelectRelation relation = executor.analyze("select * from sys.nodes where null is null");
        assertThat(relation.where()).isEqualTo(Literal.BOOLEAN_TRUE);
    }

    @Test
    public void testLongIsNullInWhereQuery() {
        var executor = SQLExecutor.of(clusterService);
        QueriedSelectRelation relation = executor.analyze("select * from sys.nodes where 1 is null");
        assertThat(relation.where()).isSQL("false");
    }

    @Test
    public void testNotPredicate() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        QueriedSelectRelation relation = executor.analyze("select * from users where name not like 'foo%'");
        assertThat(((Function) relation.where()).name()).isEqualTo(NotPredicate.NAME);
    }

    @Test
    public void testFilterByLiteralBoolean() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        QueriedSelectRelation relation = executor.analyze("select * from users where awesome=TRUE");
        assertThat(((Function) relation.where()).arguments().get(1).symbolType())
            .isEqualTo(SymbolType.LITERAL);
    }

    @Test
    public void testSelectColumnWitoutFromResultsInColumnUnknownException() throws Exception {
        var executor = SQLExecutor.of(clusterService);
        assertThatThrownBy(() -> executor.analyze("select 'bar', name"))
            .isExactlyInstanceOf(ColumnUnknownException.class)
            .hasMessage("Column name unknown");
    }

    @Test
    public void test2From() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        AnalyzedRelation relation = executor.analyze("select a.name from users a, users b");
        assertThat(relation).isExactlyInstanceOf(QueriedSelectRelation.class);
    }

    @Test
    public void testOrderByQualifiedName() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);

        assertThatThrownBy(() -> executor.analyze("select * from users order by friends.id"))
            .isExactlyInstanceOf(RelationUnknown.class)
            .hasMessage("Relation 'doc.friends' unknown");
    }

    @Test
    public void testNotTimestamp() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.TEST_PARTITIONED_TABLE_DEFINITION);

        assertThatThrownBy(() -> executor.analyze("select id, name from parted where not date"))
            .isExactlyInstanceOf(UnsupportedFunctionException.class)
            .hasMessage("Invalid arguments in: (NOT doc.parted.date) with (timestamp with time zone). Valid types: (boolean)");
    }

    @Test
    public void testJoin() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION)
            .addTable(TableDefinitions.USER_TABLE_MULTI_PK_DEFINITION);

        AnalyzedRelation relation = executor.analyze("select * from users, users_multi_pk where users.id = users_multi_pk.id");
        assertThat(relation).isExactlyInstanceOf(QueriedSelectRelation.class);
    }

    @Test
    public void testInnerJoinSyntaxDoesNotExtendsWhereClause() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION)
            .addTable(TableDefinitions.USER_TABLE_MULTI_PK_DEFINITION);

        QueriedSelectRelation mss = executor.analyze(
            "select * from users inner join users_multi_pk on users.id = users_multi_pk.id");
        assertThat(mss.where()).isLiteral(true);
        JoinRelation joinRelation = (JoinRelation) mss.from().getFirst();
        assertThat(joinRelation.joinCondition()).isSQL("(doc.users.id = doc.users_multi_pk.id)");
    }

    @Test
    public void testJoinSyntaxWithMoreThan2Tables() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION)
            .addTable(TableDefinitions.USER_TABLE_MULTI_PK_DEFINITION)
            .addTable(TableDefinitions.USER_TABLE_CLUSTERED_BY_ONLY_DEFINITION);

        QueriedSelectRelation relation = executor.analyze("select * from users u1 " +
                                                 "join users_multi_pk u2 on u1.id = u2.id " +
                                                 "join users_clustered_by_only u3 on u2.id = u3.id ");
        assertThat(relation.where()).isLiteral(true);

        JoinRelation joinRelation = (JoinRelation) relation.from().getFirst();
        assertThat(joinRelation.joinCondition()).isSQL("(u2.id = u3.id)");
        JoinRelation nested = (JoinRelation) joinRelation.left();
        assertThat(nested.joinCondition()).isSQL("(u1.id = u2.id)");
    }

    @Test
    public void testCrossJoinWithJoinCondition() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION)
            .addTable(TableDefinitions.USER_TABLE_MULTI_PK_DEFINITION);

        assertThatThrownBy(
            () -> executor.analyze("select * from users cross join users_multi_pk on users.id = users_multi_pk.id"))
            .isExactlyInstanceOf(ParsingException.class)
            .hasMessage("line 1:47: mismatched input 'on' expecting {<EOF>, ';'}");
    }

    @Test
    public void testJoinUsingSyntax() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION)
            .addTable(TableDefinitions.USER_TABLE_MULTI_PK_DEFINITION);

        QueriedSelectRelation relation = executor.analyze("select * from users join users_multi_pk using (id, name)");
        assertThat(relation.where()).isLiteral(true);
        JoinRelation joinRelation = (JoinRelation) relation.from().getFirst();
        assertThat(joinRelation.joinCondition())
            .isSQL("((doc.users.id = doc.users_multi_pk.id) AND (doc.users.name = doc.users_multi_pk.name))");
    }

    @Test
    public void testNaturalJoinSyntax() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION)
            .addTable(TableDefinitions.USER_TABLE_MULTI_PK_DEFINITION);

        assertThatThrownBy(() -> executor.analyze("select * from users natural join users_multi_pk"))
            .isExactlyInstanceOf(UnsupportedOperationException.class)
            .hasMessage("join criteria NaturalJoin not supported");
    }

    @Test
    public void testInnerJoinSyntaxWithWhereClause() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION)
            .addTable(TableDefinitions.USER_TABLE_MULTI_PK_DEFINITION);
        QueriedSelectRelation relation = executor.analyze(
            "select * from users join users_multi_pk on users.id = users_multi_pk.id " +
            "where users.name = 'Arthur'");

        JoinRelation joinRelation = (JoinRelation) relation.from().getFirst();
        assertThat(joinRelation.joinCondition()).isSQL("(doc.users.id = doc.users_multi_pk.id)");

        assertThat(relation.where()).isSQL("(doc.users.name = 'Arthur')");
        JoinRelation join = (JoinRelation) relation.from().getFirst();
        assertThat(join.left().relationName().fqn()).isEqualTo("doc.users");
    }

    public void testSelfJoinSyntaxWithWhereClause() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        QueriedSelectRelation relation = executor.analyze("select t2.id from users as t1 join users as t2 on t1.id = t2.id " +
                                                 "where t1.name = 'foo' and t2.name = 'bar'");

        assertThat(relation.where()).isSQL("((t1.name = 'foo') AND (t2.name = 'bar'))");
        assertThat(relation).isExactlyInstanceOf(QueriedSelectRelation.class);
    }

    @Test
    public void testJoinWithOrderBy() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION)
            .addTable(TableDefinitions.USER_TABLE_MULTI_PK_DEFINITION);
        AnalyzedRelation relation = executor.analyze("select users.id from users, users_multi_pk order by users.id");
        assertThat(relation).isExactlyInstanceOf(QueriedSelectRelation.class);

        QueriedSelectRelation mss = (QueriedSelectRelation) relation;

        assertThat(mss.orderBy()).isSQL("doc.users.id");
    }

    @Test
    public void testJoinWithOrderByOnCount() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION)
            .addTable(TableDefinitions.USER_TABLE_MULTI_PK_DEFINITION);
        AnalyzedRelation relation = executor.analyze("select count(*) from users u1, users_multi_pk u2 " +
                                            "order by 1");
        QueriedSelectRelation mss = (QueriedSelectRelation) relation;
        assertThat(mss.orderBy()).isSQL("count(*)");
    }

    @Test
    public void testJoinWithMultiRelationOrderBy() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION)
            .addTable(TableDefinitions.USER_TABLE_MULTI_PK_DEFINITION);
        AnalyzedRelation relation = executor.analyze(
            "select u1.id from users u1, users_multi_pk u2 order by u2.id, u1.name || u2.name");
        assertThat(relation).isExactlyInstanceOf(QueriedSelectRelation.class);

        QueriedSelectRelation mss = (QueriedSelectRelation) relation;
        AnalyzedRelation u1 = mss.from().getFirst();
        assertThat(u1.outputs()).anySatisfy(isField("name")).anySatisfy(isField("id"));
    }

    @Test
    public void testJoinConditionIsNotPartOfOutputs() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        AnalyzedRelation rel = executor.analyze(
            "select u1.name from users u1 inner join users u2 on u1.id = u2.id order by u2.date");
        assertThat(rel.outputs()).satisfiesExactly(isField("name"));
    }

    @Test
    public void testIntersect() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        assertThatThrownBy(() -> executor.analyze("select * from users intersect select * from users_multi_pk"))
            .isExactlyInstanceOf(UnsupportedFeatureException.class)
            .hasMessage("INTERSECT is not supported");
    }

    @Test
    public void testExcept() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        assertThatThrownBy(() -> executor.analyze("select * from users except select * from users_multi_pk"))
            .isExactlyInstanceOf(UnsupportedFeatureException.class)
            .hasMessage("EXCEPT is not supported");
    }

    @Test
    public void testArrayCompareInvalidArray() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        assertThatThrownBy(() -> executor.analyze("select * from users where 'George' = ANY (name)"))
            .isExactlyInstanceOf(UnsupportedFunctionException.class)
            .hasMessage("Invalid arguments in: ('George' = ANY(doc.users.name)) with (text, text). Valid types: (E, array(E))");
    }

    @Test
    public void testArrayCompareObjectArray() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        QueriedSelectRelation relation = executor.analyze("select * from users where {id=1} = ANY (friends)");
        assertThat(relation.where()).isFunction("any_=");
    }

    @Test
    public void testArrayCompareAny() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        QueriedSelectRelation relation = executor.analyze("select * from users where 0 = ANY (counters)");

        var func = (Function) relation.where();
        assertThat(func.name()).isEqualTo("any_=");

        relation = executor.analyze("select * from users where 0 = ANY (counters)");

        func = (Function) relation.where();
        assertThat(func.name()).isEqualTo("any_=");
    }

    @Test
    public void testArrayCompareAnyNeq() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        QueriedSelectRelation relation = executor.analyze("select * from users where 4.3 != ANY (counters)");

        var func = (Function) relation.where();
        assertThat(func.name()).isEqualTo("any_<>");
    }

    @Test
    public void testArrayCompareAll() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        QueriedSelectRelation relation = executor.analyze("select * from users where 0 = ALL (counters)");
        assertThat(relation.where()).isFunction("_all_=");
    }

    @Test
    public void testImplicitContainmentOnObjectArrayFields() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        // users.friends is an object array,
        // so its fields are selected as arrays,
        // ergo simple comparison does not work here
        assertThatThrownBy(() -> executor.analyze("select * from users where 5 = friends['id']"))
            .isExactlyInstanceOf(UnsupportedFunctionException.class)
            .hasMessage("Invalid arguments in: (doc.users.friends['id'] = 5) with (bigint_array, integer). Valid types: (E, E)");
    }

    @Test
    public void testAnyOnObjectArrayField() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        QueriedSelectRelation relation = executor.analyze(
            "select * from users where 5 = ANY (friends['id'])");
        Function anyFunction = (Function) relation.where();
        assertThat(anyFunction.name()).isEqualTo(AnyEqOperator.NAME);
        assertThat(anyFunction.arguments().get(1))
            .isReference()
            .hasName("friends['id']")
            .hasType(new ArrayType<>(DataTypes.LONG));
        assertThat(anyFunction.arguments().getFirst()).isLiteral(5L);
    }

    @Test
    public void testAnyOnArrayInObjectArray() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        QueriedSelectRelation relation = executor.analyze(
            "select * from users where ['vogon lyric lovers'] = ANY (friends['groups'])");
        assertThat(relation.where())
            .isFunction(
                "any_=",
                isLiteral(
                    List.of("vogon lyric lovers"),
                    new ArrayType<>(DataTypes.STRING)),
                isReference("friends['groups']", new ArrayType<>(new ArrayType<>(DataTypes.STRING)))
            );
    }

    @Test
    public void testTableAliasWrongUse() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        assertThatThrownBy(() -> executor.analyze("select * from users as u where users.awesome = true"))
            // caused by where users.awesome, would have to use where u.awesome = true instead
            .isExactlyInstanceOf(RelationUnknown.class)
            .hasMessage("Relation 'doc.users' unknown");
    }

    @Test
    public void testTableAliasFullQualifiedName() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        assertThatThrownBy(() -> executor.analyze("select * from users as u where doc.users.awesome = true"))
            // caused by where users.awesome, would have to use where u.awesome = true instead
            .isExactlyInstanceOf(RelationUnknown.class)
            .hasMessage("Relation 'doc.users' unknown");
    }

    @Test
    public void testAliasSubscript() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        AnalyzedRelation relation = executor.analyze(
            "select u.friends['id'] from users as u");
        assertThat(relation.outputs()).hasSize(1);
        Symbol s = relation.outputs().getFirst();
        assertThat(s).isNotNull();
        assertThat(s).isField("friends['id']");
    }

    @Test
    public void testOrderByWithOrdinal() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        QueriedSelectRelation relation = executor.analyze("select name from users u order by 1");
        assertThat(relation.outputs()).isEqualTo(relation.orderBy().orderBySymbols());
    }

    @Test
    public void testOrderByOnInterval() throws Exception {
        var executor = SQLExecutor.of(clusterService);
        QueriedSelectRelation stmt = executor.analyze("select INTERVAL '12' HOUR AS \"interval\" from sys.nodes order by 1");
        assertThat(stmt.orderBy().orderBySymbols()).satisfiesExactly(
            x -> assertThat(x)
                .isAlias("interval")
                .isLiteral(new Period(12, 0, 0, 0)
                               .withPeriodType(PeriodType.yearMonthDayTime()))
        );
        stmt = executor.analyze(
            "select current_timestamp - process['probe_timestamp'] AS \"interval\" from sys.nodes order by 1");
        assertThat(stmt.orderBy().orderBySymbols()).satisfiesExactly(
            x -> assertThat(x)
                .isAlias("interval")
                .isFunction("subtract")
        );
    }

    @Test
    public void testOrderByOnArray() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        assertThatThrownBy(() -> executor.analyze("select * from users order by friends"))
            .isExactlyInstanceOf(UnsupportedOperationException.class)
            .hasMessage("Cannot ORDER BY 'friends': invalid data type 'object_array'.");
    }

    @Test
    public void testOrderByOnObject() throws Exception {
        var executor = SQLExecutor.of(clusterService);
        assertThatThrownBy(() -> executor.analyze("select * from sys.nodes order by load"))
            .isExactlyInstanceOf(UnsupportedOperationException.class)
            .hasMessage("Cannot ORDER BY 'load': invalid data type 'object'.");
    }

    @Test
    public void testArithmeticPlus() throws Exception {
        var executor = SQLExecutor.of(clusterService);
        AnalyzedRelation relation = executor.analyze("select load['1'] + load['5'] from sys.nodes");
        assertThat(((Function) relation.outputs().getFirst()).name()).isEqualTo(ArithmeticFunctions.Names.ADD);
    }

    @Test
    public void testPrefixedNumericLiterals() throws Exception {
        var executor = SQLExecutor.of(clusterService);
        AnalyzedRelation relation = executor.analyze("select - - - 10");
        List<Symbol> outputs = relation.outputs();
        assertThat(outputs.getFirst()).isLiteral(-10);

        relation = executor.analyze("select - + - 10");
        outputs = relation.outputs();
        assertThat(outputs.getFirst()).isLiteral(10);

        relation = executor.analyze("select - (- 10 - + 10) * - (+ 10 + - 10)");
        outputs = relation.outputs();
        assertThat(outputs.getFirst()).isLiteral(0);
    }

    @Test
    public void testAnyLike() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        QueriedSelectRelation relation = executor.analyze("select * from users where 'awesome' LIKE ANY (tags)");
        Function query = (Function) relation.where();
        assertThat(query.name()).isEqualTo("any_like");
        assertThat(query.arguments()).hasSize(2);
        assertThat(query.arguments().getFirst()).isExactlyInstanceOf(Literal.class);
        assertThat(query.arguments().getFirst()).isLiteral("awesome", DataTypes.STRING);
        assertThat(query.arguments().get(1)).isReference().hasName("tags");
    }

    @Test
    public void testAnyLikeLiteralMatchAll() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        QueriedSelectRelation relation = executor.analyze("select * from users where 'awesome' LIKE ANY (['a', 'b', 'awesome'])");
        assertThat(relation.where()).isLiteral(true);
    }

    @Test
    public void testAnyLikeLiteralNoMatch() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        QueriedSelectRelation relation = executor.analyze("select * from users where 'awesome' LIKE ANY (['a', 'b'])");
        assertThat(relation.where()).isLiteral(false);
    }

    @Test
    public void testAnyNotLike() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        QueriedSelectRelation relation = executor.analyze("select * from users where 'awesome' NOT LIKE ANY (tags)");
        Function query = (Function) relation.where();
        assertThat(query.name()).isEqualTo("any_not_like");

        assertThat(query.arguments()).hasSize(2);
        assertThat(query.arguments().getFirst()).isExactlyInstanceOf(Literal.class);
        assertThat(query.arguments().getFirst()).isLiteral("awesome", DataTypes.STRING);
        assertThat(query.arguments().get(1)).isReference().hasName("tags");
    }

    @Test
    public void testAnyLikeInvalidArray() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        assertThatThrownBy(() -> executor.analyze("select * from users where 'awesome' LIKE ANY (name)"))
            .isExactlyInstanceOf(UnsupportedFunctionException.class)
            .hasMessage("Invalid arguments in: ('awesome' LIKE ANY(doc.users.name)) with (text, text). Valid types: (text, array(text))");
    }

    @Test
    public void testPositionalArgumentOrderByArrayType() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        assertThatThrownBy(() -> executor.analyze("SELECT id, friends FROM users ORDER BY 2"))
            .isExactlyInstanceOf(UnsupportedOperationException.class)
            .hasMessage("Cannot ORDER BY 'friends': invalid data type 'object_array'.");
    }

    @Test
    public void testOrderByDistanceAlias() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.TEST_DOC_LOCATIONS_TABLE_DEFINITION);
        String stmt = "SELECT distance(loc, 'POINT(-0.1275 51.507222)') AS distance_to_london " +
                      "FROM locations " +
                      "ORDER BY distance_to_london";
        testDistanceOrderBy(executor, stmt);
    }

    @Test
    public void testOrderByDistancePositionalArgument() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.TEST_DOC_LOCATIONS_TABLE_DEFINITION);
        String stmt = "SELECT distance(loc, 'POINT(-0.1275 51.507222)') " +
                      "FROM locations " +
                      "ORDER BY 1";
        testDistanceOrderBy(executor, stmt);
    }

    @Test
    public void testOrderByDistanceExplicitly() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.TEST_DOC_LOCATIONS_TABLE_DEFINITION);
        String stmt = "SELECT distance(loc, 'POINT(-0.1275 51.507222)') " +
                      "FROM locations " +
                      "ORDER BY distance(loc, 'POINT(-0.1275 51.507222)')";
        testDistanceOrderBy(executor, stmt);
    }

    @Test
    public void testOrderByDistancePermutatedExplicitly() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.TEST_DOC_LOCATIONS_TABLE_DEFINITION);
        String stmt = "SELECT distance('POINT(-0.1275 51.507222)', loc) " +
                      "FROM locations " +
                      "ORDER BY distance('POINT(-0.1275 51.507222)', loc)";
        testDistanceOrderBy(executor, stmt);
    }

    private void testDistanceOrderBy(SQLExecutor executor, String stmt) throws Exception {
        QueriedSelectRelation relation = executor.analyze(stmt);
        assertThat(relation.orderBy()).isNotNull();
        assertThat(relation.orderBy().orderBySymbols())
            .satisfiesExactly(
                (Consumer<Symbol>) symbol ->
                    anyOf(
                        toCondition(isAlias("distance_to_london", isFunction(DistanceFunction.NAME))),
                        toCondition(isFunction(DistanceFunction.NAME))));
    }

    @Test
    public void testWhereMatchOnColumn() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        QueriedSelectRelation relation = executor.analyze("select * from users where match(name, 'Arthur Dent')");
        assertThat(relation.where()).isExactlyInstanceOf(MatchPredicate.class);
        MatchPredicate matchPredicate = (MatchPredicate) relation.where();

        assertThat(matchPredicate.queryTerm()).isLiteral("Arthur Dent");
        assertThat(matchPredicate.identBoostMap()).hasEntrySatisfying(
            toCondition(isReference("name")), toCondition(isLiteral(null)));
        assertThat(matchPredicate.matchType()).isEqualTo("best_fields");
        assertThat(matchPredicate.options()).isLiteral(Map.of());
    }

    @Test
    public void testMatchOnIndex() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        QueriedSelectRelation relation = executor.analyze("select * from users where match(name_text_ft, 'Arthur Dent')");
        assertThat(relation.where()).isExactlyInstanceOf(MatchPredicate.class);
        MatchPredicate match = (MatchPredicate) relation.where();
        assertThat(match.identBoostMap()).hasEntrySatisfying(
            toCondition(isReference("name_text_ft")), toCondition(isLiteral(null)));
        assertThat(match.queryTerm()).isLiteral("Arthur Dent");
        assertThat(match.matchType()).isEqualTo("best_fields");
        assertThat(match.options()).isLiteral(Map.of());
    }

    @Test
    public void testMatchOnDynamicColumn() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        assertThatThrownBy(() -> executor.analyze("select * from users where match(details['me_not_exizzt'], 'Arthur Dent')"))
            .isExactlyInstanceOf(ColumnUnknownException.class)
            .hasMessage("Column details['me_not_exizzt'] unknown");
    }

    @Test
    public void testMatchPredicateInResultColumnList() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        assertThatThrownBy(() -> executor.analyze("select match(name, 'bar') from users"))
            .isExactlyInstanceOf(UnsupportedOperationException.class)
            .hasMessage("match predicate cannot be selected");
    }

    @Test
    public void testMatchPredicateInGroupByClause() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        assertThatThrownBy(() -> executor.analyze("select count(*) from users group by MATCH(name, 'bar')"))
            .isExactlyInstanceOf(UnsupportedOperationException.class)
            .hasMessage("match predicate cannot be used in a GROUP BY clause");
    }

    @Test
    public void testMatchPredicateInOrderByClause() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        assertThatThrownBy(() -> executor.analyze("select name from users order by match(name, 'bar')"))
            .isExactlyInstanceOf(UnsupportedOperationException.class)
            .hasMessage("match predicate cannot be used in an ORDER BY clause");
    }

    @Test
    public void test_cannot_use_match_predicate_as_sub_expression_of_order_by() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        assertThatThrownBy(() -> executor.analyze("select name from users order by match(name, 'foo') or match(name, 'bar')"))
            .isExactlyInstanceOf(UnsupportedOperationException.class)
            .hasMessage("match predicate cannot be used in an ORDER BY clause");
    }

    @Test
    public void testMatchPredicateWithWrongQueryTerm() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        assertThatThrownBy(() -> executor.analyze("select name from users order by match(name, [10, 20])"))
            .isExactlyInstanceOf(ConversionException.class)
            .hasMessage("Cannot cast expressions from type `integer_array` to type `text`");
    }

    @Test
    public void testSelectWhereSimpleMatchPredicate() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        QueriedSelectRelation relation = executor.analyze("select * from users where match (text, 'awesome')");
        assertThat(relation.where()).isExactlyInstanceOf(MatchPredicate.class);
        MatchPredicate query = (MatchPredicate) relation.where();

        assertThat(query.identBoostMap()).hasEntrySatisfying(
            toCondition(isReference("text")), toCondition(isLiteral(null)));
        assertThat(query.options()).isLiteral(Map.of());
        assertThat(query.queryTerm()).isLiteral("awesome");
        assertThat(query.matchType()).isEqualTo("best_fields");
    }

    @Test
    public void testSelectWhereFullMatchPredicate() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        QueriedSelectRelation relation = executor.analyze(
            "select * from users " +
            "where match ((name 1.2, text), 'awesome') using best_fields with (analyzer='german')");
        Symbol query = relation.where();
        assertThat(query).isExactlyInstanceOf(MatchPredicate.class);
        MatchPredicate match = (MatchPredicate) query;
        assertThat(match.identBoostMap())
            .anySatisfy((k, v) -> {
                assertThat(k).isReference().hasName("name");
                assertThat(v).isLiteral(1.2);
            })
            .anySatisfy((k, v) -> {
                assertThat(k).isReference().hasName("text");
                assertThat(v).isLiteral(null);
            });
        assertThat(match.queryTerm()).isLiteral("awesome");
        assertThat(match.matchType()).isEqualTo("best_fields");
        assertThat(match.options()).isLiteral(Map.of("analyzer", "german"));
    }

    @Test
    public void testWhereMatchUnknownType() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        assertThatThrownBy(
            () -> executor.analyze("select * from users " +
                                   "where match ((name 1.2, text), 'awesome') using some_fields"))
            .isExactlyInstanceOf(IllegalArgumentException.class)
            .hasMessage("Unknown MATCH type \"some_fields\". Valid types are: best_fields, most_fields, cross_fields, phrase, phrase_prefix");
    }

    @Test
    public void testUnknownSubscriptInSelectList() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        assertThatThrownBy(() -> executor.analyze("select o['no_such_column'] from users"))
            .isExactlyInstanceOf(ColumnUnknownException.class)
            .hasMessage("Column o['no_such_column'] unknown");
    }

    @Test
    public void testUnknownSubscriptInQuery() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        assertThatThrownBy(() -> executor.analyze("select * from users where o['no_such_column'] is not null"))
            .isExactlyInstanceOf(ColumnUnknownException.class)
            .hasMessage("Column o['no_such_column'] unknown");
    }

    @Test
    public void testWhereMatchAllowedTypes() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        QueriedSelectRelation best_fields_relation = executor.analyze("select * from users " +
                                                        "where match ((name 1.2, text), 'awesome') using best_fields");
        QueriedSelectRelation most_fields_relation = executor.analyze("select * from users " +
                                                        "where match ((name 1.2, text), 'awesome') using most_fields");
        QueriedSelectRelation cross_fields_relation = executor.analyze("select * from users " +
                                                         "where match ((name 1.2, text), 'awesome') using cross_fields");
        QueriedSelectRelation phrase_relation = executor.analyze("select * from users " +
                                                   "where match ((name 1.2, text), 'awesome') using phrase");
        QueriedSelectRelation phrase_prefix_relation = executor.analyze("select * from users " +
                                                          "where match ((name 1.2, text), 'awesome') using phrase_prefix");

        assertThat(((MatchPredicate) best_fields_relation.where()).matchType()).isEqualTo("best_fields");
        assertThat(((MatchPredicate) most_fields_relation.where()).matchType()).isEqualTo("most_fields");
        assertThat(((MatchPredicate) cross_fields_relation.where()).matchType()).isEqualTo("cross_fields");
        assertThat(((MatchPredicate) phrase_relation.where()).matchType()).isEqualTo("phrase");
        assertThat(((MatchPredicate) phrase_prefix_relation.where()).matchType()).isEqualTo("phrase_prefix");
    }

    @Test
    public void testWhereMatchAllOptions() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        QueriedSelectRelation relation = executor.analyze("select * from users " +
                                            "where match ((name 1.2, text), 'awesome') using best_fields with " +
                                            "(" +
                                            "  analyzer='german'," +
                                            "  boost=4.6," +
                                            "  tie_breaker=0.75," +
                                            "  operator='or'," +
                                            "  minimum_should_match=4," +
                                            "  fuzziness=12," +
                                            "  max_expansions=3," +
                                            "  prefix_length=4," +
                                            "  rewrite='constant_score_boolean'," +
                                            "  fuzzy_rewrite='top_terms_20'," +
                                            "  zero_terms_query='all'," +
                                            "  cutoff_frequency=5," +
                                            "  slop=3" +
                                            ")");
        MatchPredicate match = (MatchPredicate) relation.where();
        assertThat(match.options()).isLiteral(Map.ofEntries(
            Map.entry("analyzer", "german"),
            Map.entry("boost", 4.6),
            Map.entry("cutoff_frequency", 5),
            Map.entry("fuzziness", 12),
            Map.entry("fuzzy_rewrite", "top_terms_20"),
            Map.entry("max_expansions", 3),
            Map.entry("minimum_should_match", 4),
            Map.entry("operator", "or"),
            Map.entry("prefix_length", 4),
            Map.entry("rewrite", "constant_score_boolean"),
            Map.entry("slop", 3),
            Map.entry("tie_breaker", 0.75),
            Map.entry("zero_terms_query", "all")
        ));
    }

    @Test
    public void testHavingWithoutGroupBy() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        assertThatThrownBy(() -> executor.analyze("select * from users having max(bytes) > 100"))
            .isExactlyInstanceOf(IllegalArgumentException.class)
            .hasMessage("HAVING clause can only be used in GROUP BY or global aggregate queries");
    }

    @Test
    public void testGlobalAggregateHaving() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        QueriedSelectRelation relation = executor.analyze("select sum(floats) from users having sum(bytes) in (42, 43, 44)");
        Function havingFunction = (Function) relation.having();

        // assert that the in was converted to or
        assertThat(havingFunction.name()).isEqualTo(AnyEqOperator.NAME);
    }

    @Test
    public void testGlobalAggregateReference() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        assertThatThrownBy(() -> executor.analyze("select sum(floats) from users having bytes in (42, 43, 44)"))
            .isExactlyInstanceOf(IllegalArgumentException.class)
            .hasMessage("Cannot use column bytes outside of an Aggregation in HAVING clause. Only GROUP BY keys allowed here.");
    }


    @Test
    public void testScoreReferenceInvalidComparison() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        assertThatThrownBy(() -> executor.analyze("select * from users where \"_score\" = 0.9"))
            .isExactlyInstanceOf(UnsupportedOperationException.class)
            .hasMessage("System column '_score' can only be used within a '>=' comparison without any surrounded predicate");
    }

    @Test
    public void testScoreReferenceComparisonWithColumn() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        assertThatThrownBy(() -> executor.analyze("select * from users where \"_score\" >= id::float"))
            .isExactlyInstanceOf(UnsupportedOperationException.class)
            .hasMessage("System column '_score' can only be used within a '>=' comparison without any surrounded predicate");
    }

    @Test
    public void testScoreReferenceInvalidNotPredicate() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        assertThatThrownBy(() -> executor.analyze("select * from users where not \"_score\" >= 0.9"))
            .isExactlyInstanceOf(UnsupportedOperationException.class)
            .hasMessage("System column '_score' can only be used within a '>=' comparison without any surrounded predicate");
    }

    @Test
    public void testScoreReferenceInvalidLikePredicate() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        assertThatThrownBy(() -> executor.analyze("select * from users where \"_score\" in (0.9)"))
            .isExactlyInstanceOf(UnsupportedOperationException.class)
            .hasMessage("System column '_score' can only be used within a '>=' comparison without any surrounded predicate");
    }

    @Test
    public void testScoreReferenceInvalidNullPredicate() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        assertThatThrownBy(() -> executor.analyze("select * from users where \"_score\" is null"))
            .isExactlyInstanceOf(UnsupportedOperationException.class)
            .hasMessage("System column '_score' can only be used within a '>=' comparison without any surrounded predicate");
    }

    @Test
    public void testScoreReferenceInvalidNotNullPredicate() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        assertThatThrownBy(() -> executor.analyze("select * from users where \"_score\" is not null"))
            .isExactlyInstanceOf(UnsupportedOperationException.class)
            .hasMessage("System column '_score' can only be used within a '>=' comparison without any surrounded predicate");
    }


    @Test
    public void test_regex_match_on_non_string_columns_use_casts() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        QueriedSelectRelation stmt = executor.analyze("select * from users where floats ~ 'foo'");
        assertThat(stmt.where()).isSQL("(doc.users.floats ~ 'foo')");
    }

    @Test
    public void test_case_insensitive_regex_match_uses_cast_on_non_string_col() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        QueriedSelectRelation stmt = executor.analyze("select * from users where floats ~* 'foo'");
        assertThat(stmt.where()).isSQL("(doc.users.floats ~* 'foo')");
    }

    @Test
    public void testRegexpMatchNull() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        QueriedSelectRelation relation = executor.analyze("select * from users where name ~ null");
        assertThat(relation.where()).isLiteral(null);
    }

    @Test
    public void testRegexpMatch() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        QueriedSelectRelation relation = executor.analyze("select * from users where name ~ '.*foo(bar)?'");
        assertThat(((Function) relation.where()).name()).isEqualTo("op_~");
    }

    @Test
    public void testSubscriptArray() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        AnalyzedRelation relation = executor.analyze("select tags[1] from users");
        assertThat(relation.outputs().getFirst()).isFunction(SubscriptFunction.NAME);
        List<Symbol> arguments = ((Function) relation.outputs().getFirst()).arguments();
        assertThat(arguments).hasSize(2);
        assertThat(arguments.getFirst()).isReference().hasName("tags");
        assertThat(arguments.get(1)).isLiteral(1);
    }

    @Test
    public void testSubscriptArrayInvalidIndexMin() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        assertThatThrownBy(() -> executor.analyze("select tags[-2147483649] from users"))
            .isExactlyInstanceOf(ConversionException.class)
            .hasMessage("Cannot cast `-2147483649::bigint` of type `bigint` to type `integer`");
    }

    @Test
    public void testSubscriptArrayInvalidIndexMax() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        assertThatThrownBy(() -> executor.analyze("select tags[2147483648] from users"))
            .isExactlyInstanceOf(ConversionException.class)
            .hasMessage("Cannot cast `2147483648::bigint` of type `bigint` to type `integer`");
    }

    @Test
    public void testSubscriptArrayNested() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.DEEPLY_NESTED_TABLE_DEFINITION);
        AnalyzedRelation relation = executor.analyze("select tags[1]['name'] from deeply_nested");
        assertThat(relation.outputs().getFirst()).isFunction(SubscriptFunction.NAME);
        List<Symbol> arguments = ((Function) relation.outputs().getFirst()).arguments();
        assertThat(arguments).hasSize(2);
        assertThat(arguments.getFirst()).isReference().hasName("tags['name']");
        assertThat(arguments.get(1)).isLiteral(1);
    }

    @Test
    public void testSubscriptArrayInvalidNesting() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.DEEPLY_NESTED_TABLE_DEFINITION);
        AnalyzedRelation relation = executor.analyze("select tags[1]['metadata'][2] from deeply_nested");
        assertThat(relation.outputs().getFirst()).isFunction(SubscriptFunction.NAME);
        List<Symbol> arguments = ((Function) relation.outputs().getFirst()).arguments();
        assertThat(arguments).hasSize(2);
        assertThat(arguments.getFirst()).isFunction(SubscriptFunction.NAME);
        assertThat(arguments.get(1)).isLiteral(2);
        arguments = ((Function) arguments.getFirst()).arguments();
        assertThat(arguments).hasSize(2);
        assertThat(arguments.getFirst()).isReference().hasName("tags['metadata']");
        assertThat(arguments.get(1)).isLiteral(1);
    }

    @Test
    public void testSubscriptArrayAsAlias() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        AnalyzedRelation relation = executor.analyze("select tags[1] as t_alias from users");
        assertThat(relation.outputs().getFirst())
            .isAlias(
                "t_alias",
                isFunction(SubscriptFunction.NAME, isReference("tags"), isLiteral(1)));
    }

    @Test
    public void testSubscriptArrayOnScalarResult() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        QueriedSelectRelation relation = executor.analyze("select regexp_matches(name, '.*')[1] as t_alias from users order by t_alias");
        Consumer<Symbol> isRegexpMatches = isFunction(
            SubscriptFunction.NAME,
            isFunction("regexp_matches", isReference("name"), isLiteral(".*")),
            isLiteral(1)
        );
        assertThat(relation.outputs()).satisfiesExactly(isAlias("t_alias", isRegexpMatches));
        assertThat(relation.orderBy().orderBySymbols()).satisfiesExactly(isRegexpMatches);
    }

    @Test
    public void testParameterSubcriptColumn() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        assertThatThrownBy(() -> executor.analyze("select friends[?] from users"))
            .isExactlyInstanceOf(UnsupportedOperationException.class)
            .hasMessage("Parameter substitution is not supported in subscript index");
    }

    @Test
    public void testParameterSubscriptLiteral() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        assertThatThrownBy(() -> executor.analyze("select ['a','b','c'][?] from users"))
            .isExactlyInstanceOf(UnsupportedOperationException.class)
            .hasMessage("Parameter substitution is not supported in subscript index");
    }

    @Test
    public void testArraySubqueryExpression() throws Exception {
        var executor = SQLExecutor.of(clusterService);
        AnalyzedRelation relation = executor.analyze("select array(select id from sys.shards) as shards_id_array from sys.shards");
        SelectSymbol arrayProjection = (SelectSymbol) ((AliasSymbol) relation.outputs().getFirst()).symbol();
        assertThat(arrayProjection.getResultType()).isEqualTo(SelectSymbol.ResultType.SINGLE_COLUMN_MULTIPLE_VALUES);
        assertThat(arrayProjection.valueType().id()).isEqualTo(ArrayType.ID);
    }

    @Test
    public void testArraySubqueryWithMultipleColsThrowsUnsupportedSubExpression() throws Exception {
        var executor = SQLExecutor.of(clusterService);
        assertThatThrownBy(() -> executor.analyze("select array(select id, num_docs from sys.shards) as tmp from sys.shards"))
            .isExactlyInstanceOf(UnsupportedOperationException.class)
            .hasMessage("Subqueries with more than 1 column are not supported.");
    }

    @Test
    public void testCastExpression() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        AnalyzedRelation relation = executor.analyze("select cast(other_id as text) from users");
        assertThat(relation.outputs().getFirst())
            .isFunction(ExplicitCastFunction.NAME, List.of(DataTypes.LONG, DataTypes.STRING));

        relation = executor.analyze("select cast(1+1 as string) from users");
        assertThat(relation.outputs().getFirst()).isLiteral("2", DataTypes.STRING);

        relation = executor.analyze("select cast(friends['id'] as array(text)) from users");
        assertThat(relation.outputs().getFirst())
            .isFunction(ExplicitCastFunction.NAME, List.of(DataTypes.BIGINT_ARRAY, DataTypes.STRING_ARRAY));
    }

    @Test
    public void testTryCastExpression() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        AnalyzedRelation relation = executor.analyze("select try_cast(other_id as text) from users");
        assertThat(relation.outputs().getFirst())
            .isFunction(
                TryCastFunction.NAME,
                List.of(DataTypes.LONG, DataTypes.STRING));

        relation = executor.analyze("select try_cast(1+1 as string) from users");
        assertThat(relation.outputs().getFirst()).isLiteral("2", DataTypes.STRING);

        relation = executor.analyze("select try_cast(null as string) from users");
        assertThat(relation.outputs().getFirst()).isLiteral(null, DataTypes.STRING);

        relation = executor.analyze("select try_cast(counters as array(boolean)) from users");
        assertThat(relation.outputs().getFirst())
            .isFunction(
                TryCastFunction.NAME,
                List.of(DataTypes.BIGINT_ARRAY, DataTypes.BOOLEAN_ARRAY));
    }

    @Test
    public void testTryCastReturnNullWhenCastFailsOnLiterals() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        AnalyzedRelation relation = executor.analyze("select try_cast('124123asdf' as integer) from users");
        assertThat(relation.outputs().getFirst()).isLiteral(null);

        relation = executor.analyze("select try_cast(['fd', '3', '5'] as array(integer)) from users");
        assertThat(relation.outputs().getFirst()).isLiteral(Arrays.asList(null, 3, 5));

        relation = executor.analyze("select try_cast('2' as boolean) from users");
        assertThat(relation.outputs().getFirst()).isLiteral(null);
    }

    @Test
    public void testSelectWithAliasRenaming() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        AnalyzedRelation relation = executor.analyze("select text as name, name as n from users");
        assertThat(relation.outputs()).satisfiesExactly(
            isAlias("name", isReference("text")),
            isAlias("n", isReference("name")));
    }

    @Test
    public void testFunctionArgumentsCantBeAliases() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        assertThatThrownBy(() -> executor.analyze("select name as n, substr(n, 1, 1) from users"))
            .isExactlyInstanceOf(ColumnUnknownException.class)
            .hasMessage("Column n unknown");
    }

    @Test
    public void testSubscriptOnAliasShouldNotWork() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        assertThatThrownBy(() -> executor.analyze("select name as n, n[1] from users"))
            .isExactlyInstanceOf(ColumnUnknownException.class)
            .hasMessage("Column n unknown");
    }

    @Test
    public void testCanSelectColumnWithAndWithoutSubscript() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        AnalyzedRelation relation = executor.analyze("select counters, counters[1] from users");
        Symbol counters = relation.outputs().getFirst();
        Symbol countersSubscript = relation.outputs().get(1);

        assertThat(counters).isReference().hasName("counters");
        assertThat(countersSubscript).isFunction("subscript");
    }

    @Test
    public void testOrderByOnAliasWithSameColumnNameInSchema() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        // name exists in the table but isn't selected so not ambiguous
        QueriedSelectRelation relation = executor.analyze("select other_id as name from users order by name");
        assertThat(relation.outputs())
            .satisfiesExactly(isAlias("name", isReference("other_id")));
        assertThat(relation.orderBy().orderBySymbols()).satisfiesExactly(isReference("other_id"));
    }

    @Test
    public void testSelectPartitionedTableOrderBy() throws Exception {
        RelationName multiPartName = new RelationName("doc", "multi_parted");
        var executor = SQLExecutor.of(clusterService)
            .addTable(
                "create table doc.multi_parted (" +
                "   id int," +
                "   date timestamp with time zone," +
                "   num long," +
                "   obj object as (name string)" +
                ") partitioned by (date, obj['name'])",
                new PartitionName(multiPartName, Arrays.asList("1395874800000", "0")).toString(),
                new PartitionName(multiPartName, Arrays.asList("1395961200000", "-100")).toString(),
                new PartitionName(multiPartName, Arrays.asList(null, "-100")).toString()
            );
        QueriedSelectRelation relation = executor.analyze(
            "select id from multi_parted order by id, abs(num)");
        List<Symbol> symbols = relation.orderBy().orderBySymbols();
        assert symbols != null;
        assertThat(symbols).hasSize(2);
        assertThat(symbols.getFirst()).isReference().hasName("id");
        assertThat(symbols.get(1)).isFunction("abs");
    }

    @Test
    public void testExtractFunctionWithLiteral() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        AnalyzedRelation relation = executor.analyze("select extract('day' from '2012-03-24') from users");
        Symbol symbol = relation.outputs().getFirst();
        assertThat(symbol).isLiteral(24);
    }

    @Test
    public void testExtractFunctionWithWrongType() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        AnalyzedRelation relation = executor.analyze(
            "select extract(day from name::timestamp with time zone) from users");
        Symbol symbol = relation.outputs().getFirst();
        assertThat(symbol).isFunction("extract_DAY");

        Symbol argument = ((Function) symbol).arguments().getFirst();
        assertThat(argument)
            .isFunction(ExplicitCastFunction.NAME, List.of(DataTypes.STRING, DataTypes.TIMESTAMPZ));
    }

    @Test
    public void testExtractFunctionWithCorrectType() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.TEST_DOC_TRANSACTIONS_TABLE_DEFINITION);
        AnalyzedRelation relation = executor.analyze("select extract(day from timestamp) from transactions");

        Symbol symbol = relation.outputs().getFirst();
        assertThat(symbol).isFunction("extract_DAY");

        Symbol argument = ((Function) symbol).arguments().getFirst();
        assertThat(argument).isReference().hasName("timestamp");
    }

    @Test
    public void selectCurrentTimestamp() throws Exception {
        var executor = SQLExecutor.of(clusterService);
        AnalyzedRelation relation = executor.analyze("select CURRENT_TIMESTAMP from sys.cluster");
        assertThat(relation.outputs()).satisfiesExactly(isFunction("current_timestamp"));
    }

    @Test
    public void testAnyRightLiteral() throws Exception {
        var executor = SQLExecutor.of(clusterService);
        QueriedSelectRelation relation = executor.analyze("select id from sys.shards where id = any ([1,2])");
        assertThat(relation.where())
            .isFunction("any_=", List.of(DataTypes.INTEGER, new ArrayType<>(DataTypes.INTEGER)));
    }

    @Test
    public void testNonDeterministicFunctionsAreNotAllocated() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.TEST_DOC_TRANSACTIONS_TABLE_DEFINITION);
        QueriedSelectRelation relation = executor.analyze(
            "select random(), random(), random() " +
            "from transactions " +
            "where random() = 13.2 " +
            "order by 1, random(), random()");
        List<Symbol> outputs = relation.outputs();
        List<Symbol> orderBySymbols = relation.orderBy().orderBySymbols();

        // non deterministic, all equal
        assertThat(outputs.getFirst())
            .isEqualTo(outputs.get(2))
            .isEqualTo(orderBySymbols.get(1));
        // different instances
        assertThat(outputs.getFirst())
            .isNotSameAs(outputs.get(2))
            .isNotSameAs(orderBySymbols.get(1));
        assertThat(outputs.get(1))
            .isEqualTo(orderBySymbols.get(2));

        // "order by 1" references output 1, its the same
        assertThat(outputs.getFirst()).isSameAs(orderBySymbols.getFirst());
        assertThat(orderBySymbols.getFirst()).isEqualTo(orderBySymbols.get(1));

        // check where clause
        Function eqFunction = (Function) relation.where();
        Symbol whereClauseSleepFn = eqFunction.arguments().getFirst();
        assertThat(outputs.getFirst()).isEqualTo(whereClauseSleepFn);
    }

    @Test
    public void testSelectSameTableTwice() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        assertThatThrownBy(() -> executor.analyze("select * from users, users"))
            .isExactlyInstanceOf(IllegalArgumentException.class)
            .hasMessage("\"doc.users\" specified more than once in the FROM clause");
    }

    @Test
    public void testSelectSameTableTwiceWithAndWithoutSchemaName() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        assertThatThrownBy(() -> executor.analyze("select * from doc.users, users"))
            .isExactlyInstanceOf(IllegalArgumentException.class)
            .hasMessage("\"doc.users\" specified more than once in the FROM clause");
    }

    @Test
    public void testSelectSameTableTwiceWithSchemaName() throws Exception {
        var executor = SQLExecutor.of(clusterService);
        assertThatThrownBy(() -> executor.analyze("select * from sys.nodes, sys.nodes"))
            .isExactlyInstanceOf(IllegalArgumentException.class)
            .hasMessage("\"sys.nodes\" specified more than once in the FROM clause");
    }

    @Test
    public void testStarToFieldsInMultiSelect() throws Exception {
        var executor = SQLExecutor.of(clusterService);
        AnalyzedRelation relation = executor.analyze(
            "select jobs.stmt, operations.* from sys.jobs, sys.operations where jobs.id = operations.job_id");
        List<Symbol> joinOutputs = relation.outputs();

        AnalyzedRelation operations = executor.analyze("select * from sys.operations");
        List<Symbol> operationOutputs = operations.outputs();
        assertThat(joinOutputs).hasSize(operationOutputs.size() + 1);
    }

    @Test
    public void testSelectStarWithInvalidPrefix() throws Exception {
        var executor = SQLExecutor.of(clusterService);
        assertThatThrownBy(() -> executor.analyze("select foo.* from sys.operations"))
            .isExactlyInstanceOf(IllegalArgumentException.class)
            .hasMessage("The relation \"foo\" is not in the FROM clause.");
    }

    @Test
    public void testFullQualifiedStarPrefix() throws Exception {
        var executor = SQLExecutor.of(clusterService);
        AnalyzedRelation relation = executor.analyze("select sys.jobs.* from sys.jobs");
        assertThat(relation.outputs()).satisfiesExactly(
            isReference("id"),
            isReference("node"),
            isReference("started"),
            isReference("stmt"),
            isReference("username"));
    }

    @Test
    public void testFullQualifiedStarPrefixWithAliasForTable() throws Exception {
        var executor = SQLExecutor.of(clusterService);
        assertThatThrownBy(() -> executor.analyze("select sys.operations.* from sys.operations t1"))
            .isExactlyInstanceOf(IllegalArgumentException.class)
            .hasMessage("The relation \"sys.operations\" is not in the FROM clause.");
    }

    @Test
    public void testSelectStarWithTableAliasAsPrefix() throws Exception {
        var executor = SQLExecutor.of(clusterService);
        AnalyzedRelation relation = executor.analyze("select t1.* from sys.jobs t1");
        assertThat(relation.outputs()).satisfiesExactly(
            isField("id"),
            isField("node"),
            isField("started"),
            isField("stmt"),
            isField("username"));
    }

    @Test
    public void testAmbiguousStarPrefix() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable("create table foo.users (id bigint primary key, name text)")
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        assertThatThrownBy(() -> executor.analyze("select users.* from doc.users, foo.users"))
            .isExactlyInstanceOf(IllegalArgumentException.class)
            .hasMessage("The referenced relation \"users\" is ambiguous.");
    }

    @Test
    public void testSelectMatchOnGeoShape() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        QueriedSelectRelation relation = executor.analyze(
            "select * from users where match(shape, 'POLYGON ((30 10, 40 40, 20 40, 10 20, 30 10))')");
        assertThat(relation.where()).isExactlyInstanceOf(MatchPredicate.class);
    }

    @Test
    public void testSelectMatchOnGeoShapeObjectLiteral() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        QueriedSelectRelation relation = executor.analyze(
            "select * from users where match(shape, {type='Polygon', coordinates=[[[30, 10], [40, 40], [20, 40], [10, 20], [30, 10]]]})");
        assertThat(relation.where()).isExactlyInstanceOf(MatchPredicate.class);
    }

    @Test
    public void testOrderByGeoShape() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        assertThatThrownBy(() -> executor.analyze("select * from users ORDER BY shape"))
            .isExactlyInstanceOf(UnsupportedOperationException.class)
            .hasMessage("Cannot ORDER BY 'shape': invalid data type 'geo_shape'.");
    }

    @Test
    public void test_cannot_use_geo_shape_as_second_expression_of_order_by() throws IOException {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        assertThatThrownBy(() -> executor.analyze("select * from users ORDER BY abs(shorts), shape"))
            .isExactlyInstanceOf(UnsupportedOperationException.class)
            .hasMessage("Cannot ORDER BY 'shape': invalid data type 'geo_shape'.");
    }

    @Test
    public void testSelectStarFromUnnest() throws Exception {
        var executor = SQLExecutor.of(clusterService);
        AnalyzedRelation relation = executor.analyze("select * from unnest([1, 2], ['Marvin', 'Trillian'])");
        //noinspection generics
        assertThat(relation.outputs())
            .satisfiesExactly(isReference("col1"), isReference("col2"));
    }

    @Test
    public void testSelectStarFromUnnestWithInvalidArguments() throws Exception {
        var executor = SQLExecutor.of(clusterService);
        assertThatThrownBy(() -> executor.analyze("select * from unnest(1, 'foo')"))
            .isExactlyInstanceOf(UnsupportedFunctionException.class)
            .hasMessage("Invalid arguments in: unnest(1, 'foo') with (integer, text). Valid types: (array(N)), ()");
    }

    @Test
    public void testSelectCol1FromUnnest() throws Exception {
        var executor = SQLExecutor.of(clusterService);
        AnalyzedRelation relation = executor.analyze("select col1 from unnest([1, 2], ['Marvin', 'Trillian'])");
        assertThat(relation.outputs()).satisfiesExactly(isReference("col1"));
    }

    @Test
    public void testCollectSetCanBeUsedInHaving() throws Exception {
        var executor = SQLExecutor.of(clusterService);
        QueriedSelectRelation relation = executor.analyze(
            "select collect_set(recovery['size']['percent']), schema_name, table_name " +
            "from sys.shards " +
            "group by 2, 3 " +
            "having collect_set(recovery['size']['percent']) != [100.0] " +
            "order by 2, 3");
        assertThat(relation.having()).isNotNull();
        assertThat(relation.having())
            .isSQL("(NOT (collect_set(sys.shards.recovery['size']['percent']) = [100.0]))");
    }

    @Test
    public void testNegationOfNonNumericLiteralsShouldFail() throws Exception {
        var executor = SQLExecutor.of(clusterService);
        assertThatThrownBy(() -> executor.analyze("select - 'foo'"))
            .isExactlyInstanceOf(UnsupportedOperationException.class)
            .hasMessage("Cannot negate 'foo'. You may need to add explicit type casts");
    }

    @Test
    public void testMatchInExplicitJoinConditionIsProhibited() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        assertThatThrownBy(() -> executor.analyze("select * from users u1 inner join users u2 on match((u1.name, u2.name), 'foo')"))
            .isExactlyInstanceOf(IllegalArgumentException.class)
            .hasMessage("Cannot use MATCH predicates on columns of 2 different relations");
    }

    @Test
    public void testUnnestWithMoreThat10Columns() {
        var executor = SQLExecutor.of(clusterService);
        AnalyzedRelation relation =
            executor.analyze("select * from unnest(['a'], ['b'], [0], [0], [0], [0], [0], [0], [0], [0], [0])");
        assertThat(relation.outputs()).satisfiesExactly(
            isReference("col1"),
            isReference("col2"),
            isReference("col3"),
            isReference("col4"),
            isReference("col5"),
            isReference("col6"),
            isReference("col7"),
            isReference("col8"),
            isReference("col9"),
            isReference("col10"),
            isReference("col11"));
    }

    @Test
    public void testUnnestWithObjectColumn() {
        var executor = SQLExecutor.of(clusterService);
        QueriedSelectRelation rel = executor.analyze("select unnest['x'] from unnest([{x=1}])");
        assertThat(rel.outputs())
            .satisfiesExactly(
                isFunction("subscript_obj", isReference("unnest"), isLiteral("x")));
    }

    @Test
    public void testScalarCanBeUsedInFromClause() {
        var executor = SQLExecutor.of(clusterService);
        QueriedSelectRelation relation = executor.analyze("select * from abs(1)");
        assertThat(relation.outputs()).satisfiesExactly(isReference("abs"));
        assertThat(relation.from().getFirst()).isExactlyInstanceOf(TableFunctionRelation.class);
    }

    @Test
    public void testCannotUseSameTableNameMoreThanOnce() {
        var executor = SQLExecutor.of(clusterService);
        assertThatThrownBy(() -> executor.analyze("select * from abs(1), abs(5)"))
            .isExactlyInstanceOf(IllegalArgumentException.class)
            .hasMessage("\"abs\" specified more than once in the FROM clause");
    }

    @Test
    public void testWindowFunctionCannotBeUsedInFromClause() {
        var executor = SQLExecutor.of(clusterService);
        assertThatThrownBy(() -> executor.analyze("select * from row_number()"))
            .isExactlyInstanceOf(UnsupportedOperationException.class)
            .hasMessage("Window or Aggregate function: 'row_number' is not allowed in function in FROM clause");
    }

    @Test
    public void testAggregateCannotBeUsedInFromClause() {
        var executor = SQLExecutor.of(clusterService);
        assertThatThrownBy(() -> executor.analyze("select * from count()"))
            .isExactlyInstanceOf(UnsupportedOperationException.class)
            .hasMessage("Window or Aggregate function: 'count' is not allowed in function in FROM clause");
    }

    @Test
    public void testSubSelectWithAccessToGrandParentRelation() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(T3.T1_DEFINITION);
        String statement = "select (select (select 1 from t1 where grandparent.x = t1.x) from t1 as parent) from t1 as grandparent";
        assertThatThrownBy(() -> executor.analyze(statement))
            .isInstanceOf(UnsupportedOperationException.class)
            .hasMessage("Cannot use relation \"grandparent\" in this context. Can only access columns of an immediate parent, not a grandparent");
    }

    @Test
    public void testContextForExplicitJoinsPrecedesImplicitJoins() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(T3.T1_DEFINITION)
            .addTable(T3.T2_DEFINITION);
        // Inner join has to be processed before implicit cross join.
        // Inner join does not know about t1's fields (!)
        String statement = "select * from t1, t2 inner join t1 b on b.x = t1.x";
        assertThatThrownBy(() -> executor.analyze(statement))
            .isInstanceOf(UnsupportedOperationException.class)
            .hasMessage("Cannot use relation \"doc.t1\" in this context. Can only access columns of an immediate parent, not a grandparent");
    }

    @Test
    public void testColumnOutputWithSingleRowSubselect() {
        var executor = SQLExecutor.of(clusterService);
        AnalyzedRelation relation = executor.analyze("select 1 = \n (select \n 2\n)\n");
        assertThat(relation.outputs())
            .satisfiesExactly(
                isFunction("op_=", isLiteral(1), exactlyInstanceOf(SelectSymbol.class)));
    }

    @Test
    public void testTableAliasIsNotAddressableByColumnNameWithSchema() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(T3.T1_DEFINITION);
        assertThatThrownBy(() -> executor.analyze("select doc.a.x from t1 as a"))
            .isExactlyInstanceOf(RelationUnknown.class)
            .hasMessage("Relation 'doc.a' unknown");
    }

    @Test
    public void testUsingTableFunctionInGroupByIsProhibited() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(T3.T1_DEFINITION);
        assertThatThrownBy(() -> executor.analyze("select count(*) from t1 group by unnest([1])"))
            .isExactlyInstanceOf(IllegalArgumentException.class)
            .hasMessage("Table functions are not allowed in GROUP BY");
    }

    @Test
    public void test_aliased_table_function_in_group_by_is_prohibited() throws Exception {
        var executor = SQLExecutor.of(clusterService);
        assertThatThrownBy(() -> executor.analyze("select unnest([1]) as a from sys.cluster group by 1"))
            .isExactlyInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Table functions are not allowed in GROUP BY");
    }

    @Test
    public void testUsingTableFunctionInHavingIsProhibited() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(T3.T1_DEFINITION);
        assertThatThrownBy(() -> executor.analyze("select count(*) from t1 having unnest([1]) > 1"))
            .isExactlyInstanceOf(IllegalArgumentException.class)
            .hasMessage("Table functions are not allowed in HAVING");
    }

    @Test
    public void testUsingTableFunctionInWhereClauseIsNotAllowed() {
        var executor = SQLExecutor.of(clusterService);
        assertThatThrownBy(() -> executor.analyze("select * from sys.nodes where unnest([1]) = 1"))
            .isExactlyInstanceOf(UnsupportedOperationException.class)
            .hasMessage("Table functions are not allowed in WHERE");
    }


    public void testUsingWindowFunctionInGroupByIsProhibited() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(T3.T1_DEFINITION);
        assertThatThrownBy(() -> executor.analyze("select count(*) from t1 group by sum(1) OVER()"))
            .isExactlyInstanceOf(IllegalArgumentException.class)
            .hasMessage("Window functions are not allowed in GROUP BY");
    }

    @Test
    public void testUsingWindowFunctionInHavingIsProhibited() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(T3.T1_DEFINITION);
        assertThatThrownBy(() -> executor.analyze("select count(*) from t1 having sum(1) OVER() > 1"))
            .isExactlyInstanceOf(IllegalArgumentException.class)
            .hasMessage("Window functions are not allowed in HAVING");
    }

    @Test
    public void testUsingWindowFunctionInWhereClauseIsNotAllowed() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(T3.T1_DEFINITION);
        assertThatThrownBy(() -> executor.analyze("select count(*) from t1 where sum(1) OVER() = 1"))
            .isExactlyInstanceOf(IllegalArgumentException.class)
            .hasMessage("Window functions are not allowed in WHERE");
    }

    @Test
    public void testCastToNestedArrayCanBeUsed() {
        var executor = SQLExecutor.of(clusterService);
        AnalyzedRelation relation = executor.analyze("select [[1, 2, 3]]::array(array(int))");
        assertThat(relation.outputs().getFirst().valueType()).isEqualTo(new ArrayType<>(DataTypes.INTEGER_ARRAY));
    }

    @Test
    public void testCastTimestampFromStringLiteral() {
        var executor = SQLExecutor.of(clusterService);
        AnalyzedRelation relation = executor.analyze("select timestamp '2018-12-12T00:00:00'");
        assertThat(relation.outputs().getFirst().valueType()).isEqualTo(DataTypes.TIMESTAMP);
    }

    @Test
    public void testCastTimestampWithoutTimeZoneFromStringLiteralUsingSQLStandardFormat() {
        var executor = SQLExecutor.of(clusterService);
        AnalyzedRelation relation = executor.analyze("select timestamp without time zone '2018-12-12 00:00:00'");
        assertThat(relation.outputs().getFirst().valueType()).isEqualTo(DataTypes.TIMESTAMP);
    }

    @Test
    public void test_cast_time_from_string_literal() {
        var executor = SQLExecutor.of(clusterService);
        AnalyzedRelation relation = executor.analyze("select time with time zone '23:59:59.999+02'");
        assertThat(relation.outputs().getFirst().valueType()).isEqualTo(DataTypes.TIMETZ);
        assertThat(relation.outputs().getFirst()).hasToString("23:59:59.999+02:00");

        relation = executor.analyze("select '23:59:59.999+02'::timetz");
        assertThat(relation.outputs().getFirst().valueType()).isEqualTo(DataTypes.TIMETZ);
        assertThat(relation.outputs().getFirst()).hasToString(new TimeTZ(86399999000L, 7200).toString());
    }

    @Test
    public void test_element_within_object_array_of_derived_table_can_be_accessed_using_subscript() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        QueriedSelectRelation relation = executor.analyze("select s.friends['id'] from (select friends from doc.users) s");
        assertThat(relation.outputs()).satisfiesExactly(isField("friends['id']"));
    }

    @Test
    public void test_can_access_element_within_object_array_of_derived_table_containing_a_join() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        AnalyzedRelation relation = executor.analyze("select joined.f1['id'], joined.f2['id'] from " +
                "(select u1.friends as f1, u2.friends as f2 from doc.users u1, doc.users u2) joined");
        assertThat(relation.outputs())
            .satisfiesExactly(
                isFunction(SubscriptFunction.NAME, isField("f1"), isLiteral("id")),
                isFunction(SubscriptFunction.NAME, isField("f2"), isLiteral("id")));
    }

    @Test
    public void test_can_access_element_within_object_array_of_derived_table_containing_a_join_with_ambiguous_column_name() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        assertThatThrownBy(
            () -> executor.analyze("select joined.friends['id'] from " +
                "(select u1.friends, u2.friends from doc.users u1, doc.users u2) joined"))
            .isExactlyInstanceOf(AmbiguousColumnException.class)
            .hasMessage("Column \"friends['id']\" is ambiguous");
    }

    @Test
    public void test_can_access_element_within_object_array_of_derived_table_containing_a_union() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        AnalyzedRelation relation = executor.analyze("select joined.f1['id'] from" +
                "  (select friends as f1 from doc.users u1 " +
                "   union all" +
                "   select friends from doc.users u2) as joined");
        assertThat(relation.outputs()).satisfiesExactly(
            isFunction(
                SubscriptFunction.NAME,
                isField("f1"),
                isLiteral("id")
            ));
    }

    @Test
    public void test_select_from_unknown_schema_has_suggestion_for_correct_schema() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        assertThatThrownBy(() -> executor.analyze("select * from \"Doc\".users"))
            .isExactlyInstanceOf(SchemaUnknownException.class)
            .hasMessage("Schema 'Doc' unknown. Maybe you meant 'doc'");
    }

    @Test
    public void test_select_from_unkown_table_has_suggestion_for_correct_table() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        assertThatThrownBy(() -> executor.analyze("select * from uusers"))
            .isExactlyInstanceOf(RelationUnknown.class)
            .hasMessage("Relation 'uusers' unknown. Maybe you meant 'users'");
    }

    @Test
    public void test_select_from_unkown_table_has_suggestion_for_similar_tables() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable("create table fooobar (id bigint primary key, name text)")
            .addTable("create table \"Foobaarr\" (id bigint primary key, name text)");
        assertThatThrownBy(() -> executor.analyze("select * from foobar"))
            .isExactlyInstanceOf(RelationUnknown.class)
            .hasMessage("Relation 'foobar' unknown. Maybe you meant one of: fooobar, \"Foobaarr\"");
    }

    @Test
    public void test_nested_column_of_object_can_be_selected_using_composite_type_access_syntax() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION);
        AnalyzedRelation relation = executor.analyze("select (address).postcode from users");
        assertThat(relation.outputs()).satisfiesExactly(isReference("address['postcode']"));
    }

    @Test
    public void test_deep_nested_column_of_object_can_be_selected_using_composite_type_access_syntax() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.DEEPLY_NESTED_TABLE_DEFINITION);
        AnalyzedRelation relation = executor.analyze("select ((details).stuff).name from deeply_nested");
        assertThat(relation.outputs()).satisfiesExactly(isReference("details['stuff']['name']"));
    }

    @Test
    public void test_record_subscript_syntax_can_be_used_on_object_literals() {
        var executor = SQLExecutor.of(clusterService);
        AnalyzedRelation rel = executor.analyze("select ({x=10}).x");
        assertThat(rel.outputs()).satisfiesExactly(isLiteral(10));
    }

    @Test
    public void test_table_function_with_multiple_columns_in_select_list_has_row_type() {
        var executor = SQLExecutor.of(clusterService);
        AnalyzedRelation rel = executor.analyze("select unnest([1, 2], [3, 4])");
        assertThat(rel.outputs().getFirst().valueType().getName()).isEqualTo("record");
    }

    @Test
    public void test_select_sys_columns_on_aliased_table() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable(T3.T1_DEFINITION);
        AnalyzedRelation rel = executor.analyze("SELECT t._score, t._id, t._version, t._score, t._uid, t._doc, t._raw, t._primary_term FROM t1 as t");
        assertThat(rel.outputs()).hasSize(8);
    }

    @Test
    public void test_match_with_geo_shape_is_streamed_as_text_type_to_4_1_8_nodes() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable("create table test (shape GEO_SHAPE)");

        String stmt = "SELECT * FROM test WHERE MATCH (shape, 'POINT(1.2 1.3)')";
        QueriedSelectRelation rel = executor.analyze(stmt);
        Symbol where = rel.where();
        assertThat(where).isExactlyInstanceOf(MatchPredicate.class);

        DocTableInfo table = executor.resolveTableInfo("test");
        EvaluatingNormalizer normalizer = new EvaluatingNormalizer(
            executor.nodeCtx,
            RowGranularity.DOC,
            null,
            new DocTableRelation(table)
        );
        Symbol normalized = normalizer.normalize(where, CoordinatorTxnCtx.systemTransactionContext());
        assertThat(normalized).isFunction("match");
        Function match = (Function) normalized;
        assertThat(match.arguments().get(1).valueType()).isEqualTo(DataTypes.GEO_SHAPE);
        assertThat(match.signature().getArgumentDataTypes().get(1)).isEqualTo(DataTypes.GEO_SHAPE);

        BytesStreamOutput out = new BytesStreamOutput();
        out.setVersion(Version.V_4_1_8);
        match.writeTo(out);

        StreamInput in = out.bytes().streamInput();
        in.setVersion(Version.V_4_1_8);
        Function serializedTo41 = new Function(in);
        assertThat(serializedTo41.signature().getArgumentDataTypes().get(1)).isEqualTo(DataTypes.STRING);
    }

    @Test
    public void test_table_function_wrapped_inside_scalar_can_be_used_inside_group_by() {
        var executor = SQLExecutor.of(clusterService);
        AnalyzedRelation rel = executor.analyze("select regexp_matches('foo', '.*')[1] from sys.cluster group by 1");
        assertThat(rel.outputs().getFirst().valueType().getName()).isEqualTo("text");
    }

    @Test
    public void test_cast_expression_with_parameterized_bit() {
        var executor = SQLExecutor.of(clusterService);
        Symbol symbol = executor.asSymbol("B'0010'::bit(3)");
        assertThat(symbol).isLiteral(BitString.ofRawBits("001"));
    }

    @Test
    public void test_cast_expression_with_parameterized_varchar() {
        var executor = SQLExecutor.of(clusterService);
        Symbol symbol = executor.asSymbol("'foo'::varchar(2)");
        assertThat(symbol).isLiteral("fo");
    }

    @Test
    public void test_can_resolve_index_through_aliased_relation() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable("create table tbl (body text, INDEX body_ft using fulltext (body))");
        String statement = "select * from tbl t where match (t.body_ft, 'foo')";
        QueriedSelectRelation rel = executor.analyze(statement);
        assertThat(rel.outputs()).satisfiesExactly(isField("body"));
        assertThat(rel.where())
            .isSQL("MATCH((t.body_ft NULL), 'foo') USING best_fields WITH ({})");
    }

    @Test
    public void testSubscriptExpressionWithUnknownRootWithSessionSetting() throws Exception {
        /*
         * create table tbl (a int);
         * select unknown['u'] from tbl; --> ColumnUnknownException
         * set errorOnUnknownObjectKey = false;
         * select unknown['u'] from tbl; --> ColumnUnknownException
         */
        var executor = SQLExecutor.of(clusterService)
            .addTable("CREATE TABLE tbl (a int)");
        executor.getSessionSettings().setErrorOnUnknownObjectKey(true);
        assertThatThrownBy(() -> executor.analyze("select unknown['u'] from tbl"))
            .isExactlyInstanceOf(ColumnUnknownException.class)
            .hasMessageContaining("Column unknown['u'] unknown");
        executor.getSessionSettings().setErrorOnUnknownObjectKey(false);
        assertThatThrownBy(() -> executor.analyze("select unknown['u'] from tbl"))
            .isExactlyInstanceOf(ColumnUnknownException.class)
            .hasMessageContaining("Column unknown['u'] unknown");
    }

    @Test
    public void testSubscriptExpressionWithUnknownObjectKeyWithSessionSetting() throws Exception {
        /*
         * CREATE TABLE tbl (obj object, obj_n object as (obj_n2 object));
         * select obj['u']             from tbl; --> ColumnUnknownException
         * select obj_n['obj_n2']['u'] from tbl; --> ColumnUnknownException
         * set errorOnUnknownObjectKey = false;
         * select obj['u']             from tbl; --> works
         * select obj_n['obj_n2']['u'] from tbl; --> works
         */
        var executor = SQLExecutor.of(clusterService)
            .addTable("CREATE TABLE tbl (obj object, obj_n object as (obj_n2 object))");
        executor.getSessionSettings().setErrorOnUnknownObjectKey(true);
        assertThatThrownBy(() -> executor.analyze("select obj['u'] from tbl"))
            .isExactlyInstanceOf(ColumnUnknownException.class)
            .hasMessageContaining("Column obj['u'] unknown");
        assertThatThrownBy(() -> executor.analyze("select obj_n['obj_n2']['u'] from tbl"))
            .isExactlyInstanceOf(ColumnUnknownException.class)
            .hasMessageContaining("Column obj_n['obj_n2']['u'] unknown");
        executor.getSessionSettings().setErrorOnUnknownObjectKey(false);
        var analyzed = executor.analyze("select obj['u'] from tbl");
        assertThat(analyzed.outputs()).hasSize(1);
        assertThat(analyzed.outputs().getFirst()).isVoidReference().hasName("obj['u']");
        analyzed = executor.analyze("select obj_n['obj_n2']['u'] from tbl");
        assertThat(analyzed.outputs()).hasSize(1);
        assertThat(analyzed.outputs().getFirst()).isVoidReference().hasName("obj_n['obj_n2']['u']");
    }

    @Test
    public void testSubscriptExpressionFromSelectLiteralWithSessionSetting() throws Exception {
        /*
         * SELECT ''::OBJECT['x']; --> ColumnUnknownException
         * set errorOnUnknownObjectKey = false;
         * SELECT ''::OBJECT['x']; --> works
         */
        var executor = SQLExecutor.of(clusterService);
        executor.getSessionSettings().setErrorOnUnknownObjectKey(true);
        assertThatThrownBy(() -> executor.analyze("SELECT ''::OBJECT['x']"))
            .isExactlyInstanceOf(ColumnUnknownException.class)
            .hasMessageContaining("The cast of `''` to return type `OBJECT(DYNAMIC)` does not contain the key `x`.\n" +
                "Consider to include inner type definition in the `OBJECT` type while casting, disable DYNAMIC unknown key errors by the `error_on_unknown_object_key` setting or cast to `OBJECT(IGNORED)`.");
        executor.getSessionSettings().setErrorOnUnknownObjectKey(false);
        var analyzed = executor.analyze("SELECT ''::OBJECT['x']");
        assertThat(analyzed.outputs()).hasSize(1);
        assertThat(analyzed.outputs().getFirst()).isLiteral(null);

        executor.getSessionSettings().setErrorOnUnknownObjectKey(true);
        assertThatThrownBy(() -> executor.analyze("select (['{\"x\":1,\"y\":2}','{\"y\":2,\"z\":3}']::ARRAY(OBJECT))['x']"))
            .isExactlyInstanceOf(ColumnUnknownException.class)
            .hasMessageContaining("The return type `ARRAY(OBJECT(DYNAMIC))` of the expression `[cast('{\"x\":1,\"y\":2}' AS OBJECT(DYNAMIC)), cast('{\"y\":2,\"z\":3}' AS OBJECT(DYNAMIC))]` does not contain the key `x`");
        executor.getSessionSettings().setErrorOnUnknownObjectKey(false);
        analyzed = executor.analyze("select (['{\"x\":1,\"y\":2}','{\"y\":2,\"z\":3}']::ARRAY(OBJECT))['x']");
        assertThat(analyzed.outputs()).hasSize(1);
        assertThat(analyzed.outputs().getFirst()).hasToString("[1, NULL]");
    }

    @Test
    public void testRecordSubscriptWithUnknownObjectKeyWithSessionSetting() throws Exception {
        /*
         * This is documenting a bug. If this fails, it is a breaking change.
         * CREATE TABLE tbl (obj object(dynamic));
         * select (obj).y from tbl; --> works --> bug
         * set errorOnUnknownObjectKey = false;
         * select (obj).y from tbl; --> works
         */
        var executor = SQLExecutor.of(clusterService)
            .addTable("CREATE TABLE tbl (obj object(dynamic))");
        executor.getSessionSettings().setErrorOnUnknownObjectKey(true);
        var analyzed = executor.analyze("select (obj).y from tbl");
        assertThat(analyzed.outputs()).hasSize(1);
        assertThat(analyzed.outputs().getFirst()).isFunction("subscript_obj", isReference("obj"), isLiteral("y"));
        executor.getSessionSettings().setErrorOnUnknownObjectKey(false);
        analyzed = executor.analyze("select (obj).y from tbl");
        assertThat(analyzed.outputs()).hasSize(1);
        assertThat(analyzed.outputs().getFirst()).isVoidReference().hasName("obj['y']");

        /*
         * select ('{}'::object).x; --> ColumnUnknownException
         * set errorOnUnknownObjectKey = false;
         * select ('{}'::object).x; --> works
         */
        executor.getSessionSettings().setErrorOnUnknownObjectKey(true);
        assertThatThrownBy(() -> executor.analyze("select ('{}'::object).x"))
            .isExactlyInstanceOf(ColumnUnknownException.class)
            .hasMessageContaining("The object `{}` does not contain the key `x`");
        executor.getSessionSettings().setErrorOnUnknownObjectKey(false);
        analyzed = executor.analyze("select ('{}'::object).x");
        assertThat(analyzed.outputs()).hasSize(1);
        assertThat(analyzed.outputs().getFirst()).isLiteral(null);
    }

    @Test
    public void testAmbiguousSubscriptExpressionWithUnknownObjectKeyToDynamicObjectsWithSessionSetting() throws Exception {
        /*
         * CREATE TABLE c1 (obj_dynamic object (dynamic) as (x int))
         * CREATE TABLE c2 (obj_dynamic object (dynamic) as (y int))
         *
         * select obj_dynamic      from c1, c2 --> AmbiguousColumnException
         * select obj_dynamic['x'] from c1, c2 --> works
         * select obj_dynamic['y'] from c1, c2 --> works
         * select obj_dynamic['z'] from c1, c2 --> AmbiguousColumnException
         * set errorOnUnknownObjectKey = false;
         * select obj_dynamic      from c1, c2 --> AmbiguousColumnException
         * select obj_dynamic['x'] from c1, c2 --> works
         * select obj_dynamic['y'] from c1, c2 --> works
         * select obj_dynamic['z'] from c1, c2 --> AmbiguousColumnException
         */

        var executor = SQLExecutor.of(clusterService)
            .addTable("CREATE TABLE c1 (obj_dynamic object (dynamic) as (x int))")
            .addTable("CREATE TABLE c2 (obj_dynamic object (dynamic) as (y int))");
        executor.getSessionSettings().setErrorOnUnknownObjectKey(true);
        assertThatThrownBy(() -> executor.analyze("select obj_dynamic from c1, c2"))
            .isExactlyInstanceOf(AmbiguousColumnException.class)
            .hasMessageContaining("Column \"obj_dynamic\" is ambiguous");
        var analyzed = executor.analyze("select obj_dynamic['x'] from c1, c2");
        assertThat(analyzed.outputs()).hasSize(1);
        assertThat(analyzed.outputs().getFirst()).isReference().hasName("obj_dynamic['x']");
        analyzed = executor.analyze("select obj_dynamic['y'] from c1, c2");
        assertThat(analyzed.outputs()).hasSize(1);
        assertThat(analyzed.outputs().getFirst()).isReference().hasName("obj_dynamic['y']");
        assertThatThrownBy(() -> executor.analyze("select obj_dynamic['z'] from c1, c2"))
            .isExactlyInstanceOf(AmbiguousColumnException.class)
            .hasMessageContaining("Column \"obj_dynamic\" is ambiguous");
        executor.getSessionSettings().setErrorOnUnknownObjectKey(false);
        assertThatThrownBy(() -> executor.analyze("select obj_dynamic from c1, c2"))
            .isExactlyInstanceOf(AmbiguousColumnException.class)
            .hasMessageContaining("Column \"obj_dynamic\" is ambiguous");
        analyzed = executor.analyze("select obj_dynamic['x'] from c1, c2");
        assertThat(analyzed.outputs()).hasSize(1);
        assertThat(analyzed.outputs().getFirst()).isReference().hasName("obj_dynamic['x']");
        analyzed = executor.analyze("select obj_dynamic['y'] from c1, c2");
        assertThat(analyzed.outputs()).hasSize(1);
        assertThat(analyzed.outputs().getFirst()).isReference().hasName("obj_dynamic['y']");
        assertThatThrownBy(() -> executor.analyze("select obj_dynamic['z'] from c1, c2"))
            .isExactlyInstanceOf(AmbiguousColumnException.class)
            .hasMessageContaining("Column \"obj_dynamic\" is ambiguous");
    }

    @Test
    public void testAmbiguousSubscriptExpressionWithUnknownObjectKeyToStrictObjectsWithSessionSetting() throws Exception {
        /*
         * CREATE TABLE c1 (obj_strict object (strict) as (x int))
         * CREATE TABLE c2 (obj_strict object (strict) as (y int))
         *
         * select obj_strict      from c1, c2 --> AmbiguousColumnException
         * select obj_strict['x'] from c1, c2 --> works
         * select obj_strict['y'] from c1, c2 --> works
         * select obj_strict['z'] from c1, c2 --> AmbiguousColumnException
         * set errorOnUnknownObjectKey = false;
         * select obj_strict      from c1, c2 --> AmbiguousColumnException
         * select obj_strict['x'] from c1, c2 --> works
         * select obj_strict['y'] from c1, c2 --> works
         * select obj_strict['z'] from c1, c2 --> AmbiguousColumnException
         */

        var executor = SQLExecutor.of(clusterService)
            .addTable("CREATE TABLE c1 (obj_strict object (strict) as (x int))")
            .addTable("CREATE TABLE c2 (obj_strict object (strict) as (y int))");
        executor.getSessionSettings().setErrorOnUnknownObjectKey(true);
        assertThatThrownBy(() -> executor.analyze("select obj_strict from c1, c2"))
            .isExactlyInstanceOf(AmbiguousColumnException.class)
            .hasMessageContaining("Column \"obj_strict\" is ambiguous");
        var analyzed = executor.analyze("select obj_strict['x'] from c1, c2");
        assertThat(analyzed.outputs()).hasSize(1);
        assertThat(analyzed.outputs().getFirst()).isReference().hasName("obj_strict['x']");
        analyzed = executor.analyze("select obj_strict['y'] from c1, c2");
        assertThat(analyzed.outputs()).hasSize(1);
        assertThat(analyzed.outputs().getFirst()).isReference().hasName("obj_strict['y']");
        assertThatThrownBy(() -> executor.analyze("select obj_strict['z'] from c1, c2"))
            .isExactlyInstanceOf(AmbiguousColumnException.class)
            .hasMessageContaining("Column \"obj_strict\" is ambiguous");
        executor.getSessionSettings().setErrorOnUnknownObjectKey(false);
        assertThatThrownBy(() -> executor.analyze("select obj_strict from c1, c2"))
            .isExactlyInstanceOf(AmbiguousColumnException.class)
            .hasMessageContaining("Column \"obj_strict\" is ambiguous");
        analyzed = executor.analyze("select obj_strict['x'] from c1, c2");
        assertThat(analyzed.outputs()).hasSize(1);
        assertThat(analyzed.outputs().getFirst()).isReference().hasName("obj_strict['x']");
        analyzed = executor.analyze("select obj_strict['y'] from c1, c2");
        assertThat(analyzed.outputs()).hasSize(1);
        assertThat(analyzed.outputs().getFirst()).isReference().hasName("obj_strict['y']");
        assertThatThrownBy(() -> executor.analyze("select obj_strict['z'] from c1, c2"))
            .isExactlyInstanceOf(AmbiguousColumnException.class)
            .hasMessageContaining("Column \"obj_strict\" is ambiguous");
    }

    @Test
    public void testAmbiguousSubscriptExpressionWithUnknownObjectKeyToIgnoredObjectsWithSessionSetting() throws Exception {
        /*
         * CREATE TABLE c3 (obj_ignored object (ignored) as (x int))
         * CREATE TABLE c4 (obj_ignored object (ignored) as (y int))
         *
         * select obj_ignored      from c3, c4 --> AmbiguousColumnException
         * select obj_ignored['x'] from c3, c4 --> AmbiguousColumnException
         * select obj_ignored['y'] from c3, c4 --> AmbiguousColumnException
         * set errorOnUnknownObjectKey = false
         * select obj_ignored      from c3, c4 --> AmbiguousColumnException
         * select obj_ignored['x'] from c3, c4 --> AmbiguousColumnException
         * select obj_ignored['y'] from c3, c4 --> AmbiguousColumnException
         */
        var executor = SQLExecutor.of(clusterService)
            .addTable("CREATE TABLE c3 (obj_ignored object (ignored) as (x int))")
            .addTable("CREATE TABLE c4 (obj_ignored object (ignored) as (y int))");
        executor.getSessionSettings().setErrorOnUnknownObjectKey(true);
        assertThatThrownBy(() -> executor.analyze("select obj_ignored from c3, c4"))
            .isExactlyInstanceOf(AmbiguousColumnException.class)
            .hasMessageContaining("Column \"obj_ignored\" is ambiguous");
        assertThatThrownBy(() -> executor.analyze("select obj_ignored['x'] from c3, c4"))
            .isExactlyInstanceOf(AmbiguousColumnException.class)
            .hasMessageContaining("Column \"obj_ignored['x']\" is ambiguous");
        assertThatThrownBy(() -> executor.analyze("select obj_ignored['y'] from c3, c4"))
            .isExactlyInstanceOf(AmbiguousColumnException.class)
            .hasMessageContaining("Column \"obj_ignored['y']\" is ambiguous");

        executor.getSessionSettings().setErrorOnUnknownObjectKey(false);
        assertThatThrownBy(() -> executor.analyze("select obj_ignored from c3, c4"))
            .isExactlyInstanceOf(AmbiguousColumnException.class)
            .hasMessageContaining("Column \"obj_ignored\" is ambiguous");
        assertThatThrownBy(() -> executor.analyze("select obj_ignored['x'] from c3, c4"))
            .isExactlyInstanceOf(AmbiguousColumnException.class)
            .hasMessageContaining("Column \"obj_ignored['x']\" is ambiguous");
        assertThatThrownBy(() -> executor.analyze("select obj_ignored['y'] from c3, c4"))
            .isExactlyInstanceOf(AmbiguousColumnException.class)
            .hasMessageContaining("Column \"obj_ignored['y']\" is ambiguous");
    }

    @Test
    public void testSubscriptExpressionWithUnknownObjectKeyFromAliasedRelationWithSessionSetting() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable("CREATE TABLE e1 (obj_dy object, obj_st object(strict))");

        executor.getSessionSettings().setErrorOnUnknownObjectKey(true);

        assertThatThrownBy(() -> executor.analyze("select obj_dy['missing_key'] from (select obj_dy from e1) alias"))
            .isExactlyInstanceOf(ColumnUnknownException.class)
            .hasMessage("Column obj_dy['missing_key'] unknown");

        assertThatThrownBy(() -> executor.analyze("select obj_st['missing_key'] from (select obj_st from e1) alias"))
            .isExactlyInstanceOf(ColumnUnknownException.class)
            .hasMessage("Column obj_st['missing_key'] unknown");

        executor.getSessionSettings().setErrorOnUnknownObjectKey(false);

        var analyzed = executor.analyze("select obj_dy['missing_key'] from (select obj_dy from e1) alias");
        assertThat(analyzed.outputs()).hasSize(1);
        assertThat(analyzed.outputs().getFirst())
            .isField("obj_dy['missing_key']");

        assertThatThrownBy(() -> executor.analyze("select obj_st['missing_key'] from (select obj_st from e1) alias"))
            .isExactlyInstanceOf(ColumnUnknownException.class)
            .hasMessage("Column obj_st['missing_key'] unknown");
    }

    @Test
    public void testSubscriptExpressionFromUnionAll() throws Exception {
        /*
         * This is documenting a bug. If this fails, it is a breaking change.
         * CREATE TABLE c1 (obj object (strict)  as (a int,        c int))
         * CREATE TABLE c2 (obj object (dynamic) as (       b int, c int))
         *
         * select obj['unknown'] from (select obj from c1 union all select obj from c1) alias;  --> throws
         * select obj['unknown'] from (select obj from c2 union all select obj from c2) alias;  --> throws
         * select obj['a']       from (select obj from c1 union all select obj from c2) alias;  --> works
         * select obj['b']       from (select obj from c1 union all select obj from c2) alias;  --> works
         * select obj['c']       from (select obj from c1 union all select obj from c2) alias;  --> works
         * select obj['unknown'] from (select obj from c1 union all select obj from c2) alias;  --> throws
         * set errorOnUnknownObjectKey = false
         * select obj['unknown'] from (select obj from c1 union all select obj from c1) alias;  --> works
         * select obj['unknown'] from (select obj from c2 union all select obj from c2) alias;  --> works
         * select obj['a']       from (select obj from c1 union all select obj from c2) alias;  --> works
         * select obj['b']       from (select obj from c1 union all select obj from c2) alias;  --> works
         * select obj['c']       from (select obj from c1 union all select obj from c2) alias;  --> works
         * select obj['unknown'] from (select obj from c1 union all select obj from c2) alias;  --> works
         */

        var executor = SQLExecutor.of(clusterService)
            .addTable("CREATE TABLE c1 (obj object (strict)  as (a int,        c int))")
            .addTable("CREATE TABLE c2 (obj object (dynamic) as (       b int, c int))");
        executor.getSessionSettings().setErrorOnUnknownObjectKey(true);

        assertThatThrownBy(() ->
            executor.analyze("select obj['unknown'] from (select obj from c1 union all select obj from c1) alias"))
            .isExactlyInstanceOf(ColumnUnknownException.class)
            .hasMessage("Column obj['unknown'] unknown");
        assertThatThrownBy(() ->
            executor.analyze("select obj['unknown'] from (select obj from c2 union all select obj from c2) alias"))
            .isExactlyInstanceOf(ColumnUnknownException.class)
            .hasMessage("Column obj['unknown'] unknown");
        var analyzed = executor.analyze("select obj['a'] from (select obj from c1 union all select obj from c2) alias");
        assertThat(analyzed.outputs()).hasSize(1);
        assertThat(analyzed.outputs().getFirst()).isFunction("subscript", isField("obj"), isLiteral("a"));
        analyzed = executor.analyze("select obj['b'] from (select obj from c1 union all select obj from c2) alias");
        assertThat(analyzed.outputs()).hasSize(1);
        assertThat(analyzed.outputs().getFirst()).isFunction("subscript", isField("obj"), isLiteral("b"));
        analyzed = executor.analyze("select obj['c'] from (select obj from c1 union all select obj from c2) alias");
        assertThat(analyzed.outputs()).hasSize(1);
        assertThat(analyzed.outputs().getFirst()).isFunction("subscript", isField("obj"), isLiteral("c"));
        assertThatThrownBy(() ->
            executor.analyze("select obj['unknown'] from (select obj from c1 union all select obj from c2) alias"))
            .isExactlyInstanceOf(ColumnUnknownException.class)
            .hasMessage("Column obj['unknown'] unknown");

        executor.getSessionSettings().setErrorOnUnknownObjectKey(false);
        analyzed = executor.analyze("select obj['unknown'] from (select obj from c1 union all select obj from c1) alias");
        assertThat(analyzed.outputs().getFirst()).isFunction("subscript", isField("obj"), isLiteral("unknown"));

        analyzed = executor.analyze("select obj['unknown'] from (select obj from c2 union all select obj from c2) alias");
        assertThat(analyzed.outputs()).hasSize(1);
        assertThat(analyzed.outputs().getFirst()).isFunction("subscript", isField("obj") ,isLiteral("unknown"));
        analyzed = executor.analyze("select obj['a'] from (select obj from c1 union all select obj from c2) alias");
        assertThat(analyzed.outputs()).hasSize(1);
        assertThat(analyzed.outputs().getFirst()).isFunction("subscript", isField("obj"), isLiteral("a"));
        analyzed = executor.analyze("select obj['b'] from (select obj from c1 union all select obj from c2) alias");
        assertThat(analyzed.outputs()).hasSize(1);
        assertThat(analyzed.outputs().getFirst()).isFunction("subscript", isField("obj"), isLiteral("b"));
        analyzed = executor.analyze("select obj['c'] from (select obj from c1 union all select obj from c2) alias");
        assertThat(analyzed.outputs()).hasSize(1);
        assertThat(analyzed.outputs().getFirst()).isFunction("subscript", isField("obj"), isLiteral("c"));
        analyzed = executor.analyze("select obj['unknown'] from (select obj from c1 union all select obj from c2) alias");
        assertThat(analyzed.outputs()).hasSize(1);
        assertThat(analyzed.outputs().getFirst()).isFunction("subscript", isField("obj"), isLiteral("unknown"));
    }

    @Test
    public void test_aliased_unknown_object_key() throws IOException {
        var executor = SQLExecutor.of(clusterService)
            .addTable("create table t (o object)");
        executor.getSessionSettings().setErrorOnUnknownObjectKey(false);
        var analyzed = executor.analyze("select alias.o['unknown_key'] from (select * from t) alias");
        assertThat(analyzed.outputs()).hasSize(1);
        assertThat(analyzed.outputs().getFirst())
            .isField("o['unknown_key']", new RelationName(null, "alias"));
    }

    @Test
    public void test_unknown_object_key_from_scoped_symbols() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable("create table t (obj array(object as (x int)))");
        assertThatThrownBy(() -> executor.analyze("select tbl.o['unknown'] from (select t.obj as o from t) tbl"))
            .isExactlyInstanceOf(ColumnUnknownException.class)
            .hasMessage("Column o['unknown'] unknown");
        executor.getSessionSettings().setErrorOnUnknownObjectKey(false);
        executor.analyze("select tbl.o['unknown'] from (select t.obj as o from t) tbl");
    }

    @Test
    public void test_unknown_object_key_from_nested_objects() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable("create table t (o array(object(ignored) as (o2 array(object(dynamic) as (o3 array(object(strict) as (a int)))))))");
        assertThatThrownBy(() -> executor.analyze("select o['o2']['unknown'] from t"))
            .isExactlyInstanceOf(ColumnUnknownException.class)
            .hasMessage("Column o['o2']['unknown'] unknown");
        assertThatThrownBy(() -> executor.analyze("select o['o2']['o3']['unknown'] from t"))
            .isExactlyInstanceOf(ColumnUnknownException.class)
            .hasMessage("Column o['o2']['o3']['unknown'] unknown");

        executor.getSessionSettings().setErrorOnUnknownObjectKey(false);

        executor.analyze("select o['o2']['unknown'] from t");
        assertThatThrownBy(() -> executor.analyze("select o['o2']['o3']['unknown'] from t"))
            .isExactlyInstanceOf(ColumnUnknownException.class)
            .hasMessage("Column o['o2']['o3']['unknown'] unknown");
    }

    @Test
    public void test_unknown_object_key_from_strict_objects() throws IOException {
        var executor = SQLExecutor.of(clusterService)
            .addTable("create table t (obj object(strict) as (a int))");
        assertThatThrownBy(() -> executor.analyze("select obj['unknown'] from t"))
            .isExactlyInstanceOf(ColumnUnknownException.class)
            .hasMessage("Column obj['unknown'] unknown");
        assertThatThrownBy(() -> executor.analyze("select tbl.o['unknown'] from (select t.obj as o from t) tbl"))
            .isExactlyInstanceOf(ColumnUnknownException.class)
            .hasMessage("Column o['unknown'] unknown");
    }

    @Test
    public void test_unknown_object_key_from_aliased_functions_shadowing_columns() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable("create table t (obj array(object as (x int)))");
        assertThatThrownBy(() -> executor.analyze(
            "select obj['unknown'] from (select unnest(obj) as obj from t) tbl"))
            .isExactlyInstanceOf(ColumnUnknownException.class)
            .hasMessage("Column obj['unknown'] unknown");
        executor.getSessionSettings().setErrorOnUnknownObjectKey(false);
        executor.analyze("select obj['unknown'] from (select unnest(obj) as obj from t) tbl");
    }

    @Test
    public void test_subscript_expression_with_aliased_subscript_expression_as_the_base() throws IOException {
        var executor = SQLExecutor.of(clusterService)
            .addTable("create table t (obj_dynamic object, obj_ignored object(ignored), obj_strict object(strict))");

        // dynamic
        assertThatThrownBy(() -> executor.analyze(
            "select alias['b'] from (select obj_dynamic['a'] as alias from t) tbl"))
            .isExactlyInstanceOf(ColumnUnknownException.class)
            .hasMessage("Column obj_dynamic['a'] unknown");

        // ignored
        var analyzed = executor.analyze("select alias['b'] from (select obj_ignored['a'] as alias from t) tbl");
        Assertions.assertThat(analyzed.outputs()).hasSize(1);
        assertThat(analyzed.outputs().getFirst()).isFunction("subscript", isField("alias"), isLiteral("b"));
        assertThat(analyzed.outputs().getFirst()).isFunction("subscript", DataTypes.UNDEFINED);

        // strict
        assertThatThrownBy(() -> executor.analyze(
            "select alias['b'] from (select obj_strict['a'] as alias from t) tbl"))
            .isExactlyInstanceOf(ColumnUnknownException.class)
            .hasMessage("Column obj_strict['a'] unknown");

        executor.getSessionSettings().setErrorOnUnknownObjectKey(false);

        // dynamic
        analyzed = executor.analyze("select alias['b'] from (select obj_dynamic['a'] as alias from t) tbl");
        Assertions.assertThat(analyzed.outputs()).hasSize(1);
        assertThat(analyzed.outputs().getFirst()).isFunction("subscript", isField("alias"), isLiteral("b"));
        assertThat(analyzed.outputs().getFirst()).isFunction("subscript", DataTypes.UNDEFINED);

        // ignored
        executor.analyze("select alias['b'] from (select obj_ignored['a'] as alias from t) tbl");
        Assertions.assertThat(analyzed.outputs()).hasSize(1);
        assertThat(analyzed.outputs().getFirst()).isFunction("subscript", isField("alias"), isLiteral("b"));
        assertThat(analyzed.outputs().getFirst()).isFunction("subscript", DataTypes.UNDEFINED);

        // strict
        assertThatThrownBy(() -> executor.analyze(
            "select alias['b'] from (select obj_strict['a'] as alias from t) tbl"))
            .isExactlyInstanceOf(ColumnUnknownException.class)
            .hasMessage("Column obj_strict['a'] unknown");
    }

    @Test
    public void test_can_use_subscript_on_aliased_functions_shadowing_columns() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable("create table t (obj array(object as (x int)))");
        QueriedSelectRelation relation = executor.analyze(
            "select obj['x'] from (select unnest(obj) as obj from t) tbl");

        assertThat(relation.outputs()).satisfiesExactly(
            output -> assertThat(output.valueType()).isEqualTo(DataTypes.INTEGER)
        );
    }

    @Test
    public void test_subscript_on_aliased_object_gets_optimized_to_reference() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable("create table t (obj array(object as (x int)))");
        QueriedSelectRelation relation = executor.analyze(
            "select obj['x'] from (select obj as obj from t) tbl");
        assertThat(relation.outputs()).satisfiesExactly(
            output -> assertThat(output.valueType()).isEqualTo(new ArrayType<>(DataTypes.INTEGER))
        );
    }

    @Test
    public void test_quote_escaped_by_backslash_at_the_end_of_c_style_string() {
        var executor = SQLExecutor.of(clusterService);

        QueriedSelectRelation relation = executor.analyze("SELECT concat(E'foo\\'', 'bar')");
        assertThat(relation.outputs()).hasSize(1);
        assertThat(relation.outputs().getFirst()).isLiteral("foo'bar");

        relation = executor.analyze("SELECT string_agg(a, e'\\'') FROM (VALUES ('1'),('2')) a(a)");
        assertThat(relation.outputs()).hasSize(1);
        assertThat(relation.outputs().getFirst()).isFunction(
            "string_agg",
            x -> assertThat(x).isScopedSymbol("a"),
            x -> assertThat(x).isLiteral("'")
        );

    }

    @Test
    public void test_result_column_type_of_nested_unnest_arg_is_not_an_array() throws Exception {
        var executor = SQLExecutor.of(clusterService);
        QueriedSelectRelation relation = executor.analyze("SELECT x from unnest([[1, 2], [3]]) as t (x)");
        assertThat(relation.outputs()).satisfiesExactly(
            x -> assertThat(x).isScopedSymbol("x")
                .hasDataType(DataTypes.INTEGER)
        );
    }

    @Test
    public void test_sub_columns_of_nested_object_arrays() throws IOException {
        var executor = SQLExecutor.of(clusterService)
            .addTable("create table t (o object as (a int)[][])");
        QueriedSelectRelation relation = executor.analyze("select o['a'] from t");
        assertThat(relation.outputs()).satisfiesExactly(
            output -> assertThat(output.valueType()).isEqualTo(makeArray(DataTypes.INTEGER, 2))
        );
    }

    @Test
    public void test_subscript_expressions_over_object_types_returned_from_functions_are_resolved_to_subscript_functions() {
        var executor = SQLExecutor.of(clusterService);
        var analyzed = executor.analyze("select o['a'] from (select {a=1} as o) tbl"); // `o` is an object literal returned from MapFunction
        Assertions.assertThat(analyzed.outputs()).hasSize(1);
        assertThat(analyzed.outputs().getFirst()).isFunction("subscript", DataTypes.INTEGER);

        analyzed = executor.analyze("select o3['a'] from (select ({a=1} || {b=1}) as o3) t2"); // `o3` is an object literal returned from ConcatFunction
        Assertions.assertThat(analyzed.outputs()).hasSize(1);
        assertThat(analyzed.outputs().getFirst()).isFunction("subscript", DataTypes.INTEGER);
    }

    @Test
    public void test_deprecation_logging_for__version_col() throws Exception {
        SQLExecutor executor = SQLExecutor.of(clusterService)
            .addTable("create table t1 (id int)");

        DocTableRelation.DEPRECATION_LOGGER.resetLRU();
        executor.analyze("select _version from t1");
        assertWarnings("_version system column is deprecated, please use _seq_no and _primary_term instead.");
    }

    /**
     * https://github.com/crate/crate/issues/17381#issuecomment-2650040614
     */
    @Test
    public void test_object_subscript_retrieval_from_join_relation_called_inside_queried_select_relation() throws Exception {
        SQLExecutor executor = SQLExecutor.of(clusterService);
        QueriedSelectRelation querySelectRelation = executor.analyze(
            """
                WITH partitions AS (
                    SELECT
                        table_schema
                    FROM
                        "information_schema"."table_partitions" AS p
                ),
                partition_allocations AS (
                    SELECT DISTINCT
                        s.schema_name AS table_schema,
                        n.attributes
                    FROM sys.shards s
                    JOIN sys.nodes n ON s.node['id'] = n.id
                )
                SELECT attributes['storage']
                FROM partitions p
                JOIN partition_allocations a ON a.table_schema = p.table_schema
                    AND attributes['storage'] <> 'warm';
                """);
        assertThat(querySelectRelation.outputs()).hasSize(1);
        assertThat(querySelectRelation.outputs().getFirst()).isScopedSymbol("attributes['storage']");
    }

    @Test
    public void test_error_on_missing_key_of_subscript_on_aliased_object_literals() {
        SQLExecutor executor = SQLExecutor.of(clusterService);

        // Field exists
        // DYNAMIC
        var analyzed = executor.analyze("SELECT o['b'] FROM (SELECT {a = {b = {c = 1}}}['a'] AS o) tbl");
        var expectedDataType = ObjectType.of(ColumnPolicy.DYNAMIC).setInnerType("c", DataTypes.INTEGER).build();
        assertThat(analyzed.outputs().getFirst()).isFunction("subscript", expectedDataType);

        // Field does not exist
        // DYNAMIC
        assertThatThrownBy(() -> executor.analyze("SELECT o['x'] FROM (SELECT {a = {b = {c = 1}}}['a'] AS o) tbl"))
            .isExactlyInstanceOf(ColumnUnknownException.class)
            .hasMessage("Column o['x'] unknown");
        // INGORED
        analyzed = executor.analyze("SELECT o['x'] FROM (SELECT {a = {b = {c = 1}}}['a']::object(ignored) AS o) tbl");
        assertThat(analyzed.outputs().getFirst()).isFunction("subscript", DataTypes.UNDEFINED);

        executor.getSessionSettings().setErrorOnUnknownObjectKey(false);

        // DYNAMIC (errors disabled)
        executor.analyze("SELECT o['x'] FROM (SELECT {a = {b = {c = 1}}}['a'] AS o) tbl");
        assertThat(analyzed.outputs().getFirst()).isFunction("subscript", DataTypes.UNDEFINED);
    }

    @Test
    public void test_accessing_sub_column_of_aliased_unknown_sub_column() throws IOException {
        var executor = SQLExecutor.of(clusterService)
            .addTable("CREATE TABLE t (obj_dynamic OBJECT AS (a OBJECT, d OBJECT AS (e OBJECT(STRICT) AS (f INT))))");

        // Field exists
        var analyzed = executor.analyze("select obj_dynamic['d']['e']['f'] from (select obj_dynamic['d'] from t) t2");
        Assertions.assertThat(analyzed.outputs()).hasSize(1);
        assertThat(analyzed.outputs().getFirst()).isFunction("subscript", DataTypes.INTEGER);

        // Field does not exist
        // DYNAMIC
        assertThatThrownBy(() -> executor.analyze("select obj_dynamic['a']['b'] from (select obj_dynamic['a'] from t) t2"))
            .isExactlyInstanceOf(ColumnUnknownException.class)
            .hasMessage("Column obj_dynamic['a']['b'] unknown");
        assertThatThrownBy(() -> executor.analyze("select obj_dynamic['a']['b']['c'] from (select obj_dynamic['a'] from t) t2"))
            .isExactlyInstanceOf(ColumnUnknownException.class)
            .hasMessage("Column obj_dynamic['a']['b']['c'] unknown");

        executor.getSessionSettings().setErrorOnUnknownObjectKey(false);

        // STRICT (always throws errors)
        assertThatThrownBy(() -> executor.analyze("select obj_dynamic['d']['e']['b'] from (select obj_dynamic['d'] from t) t2"))
            .isExactlyInstanceOf(ColumnUnknownException.class)
            .hasMessage("Column obj_dynamic['d']['e']['b'] unknown");

        // DYNAMIC (errors disabled)
        analyzed = executor.analyze("select obj_dynamic['a']['b'] from (select obj_dynamic['a'] from t) t2");
        Assertions.assertThat(analyzed.outputs()).hasSize(1);
        assertThat(analyzed.outputs().getFirst()).isFunction("subscript", DataTypes.UNDEFINED);

        analyzed = executor.analyze("select obj_dynamic['a']['b']['c'] from (select obj_dynamic['a'] from t) t2");
        Assertions.assertThat(analyzed.outputs()).hasSize(1);
        assertThat(analyzed.outputs().getFirst()).isFunction("subscript", DataTypes.UNDEFINED);

    }

    @Test
    public void test_subscript_on_aliased_json_string_cast_to_object() throws Exception {
        var executor = SQLExecutor.of(clusterService)
            .addTable("CREATE TABLE t1 (js TEXT)");

        // DYNAMIC object cast
        executor.getSessionSettings().setErrorOnUnknownObjectKey(true);
        // Subscript on literals
        assertThatThrownBy(() -> executor.analyze("SELECT '{\"a\":1}'::OBJECT['a']"))
            .isExactlyInstanceOf(ColumnUnknownException.class)
            .hasMessageContaining("The cast of `'{\"a\":1}'` to return type `OBJECT(DYNAMIC)` does not contain the key `a`.\n" +
                "Consider to include inner type definition in the `OBJECT` type while casting, disable DYNAMIC unknown key errors by the `error_on_unknown_object_key` setting or cast to `OBJECT(IGNORED)`.");
        assertThatThrownBy(() -> executor.analyze("SELECT myobj['a'] FROM (SELECT '{\"a\":1}'::OBJECT as myobj) t"))
            .isExactlyInstanceOf(ColumnUnknownException.class)
            .hasMessageContaining("Column myobj['a'] unknown");
        // Subscript on references
        assertThatThrownBy(() -> executor.analyze("SELECT js::OBJECT AS (b int)['a'] FROM t1"))
            .isExactlyInstanceOf(ColumnUnknownException.class)
            .hasMessageContaining("The cast of `doc.t1.js` to return type `OBJECT(DYNAMIC) AS (\"b\" INTEGER)` does not contain the key `a`.\n" +
                "Consider to include inner type definition in the `OBJECT` type while casting, disable DYNAMIC unknown key errors by the `error_on_unknown_object_key` setting or cast to `OBJECT(IGNORED)`.");
        assertThatThrownBy(() -> executor.analyze("SELECT myobj['a'] FROM (SELECT js::OBJECT as myobj FROM t1) t"))
            .isExactlyInstanceOf(ColumnUnknownException.class)
            .hasMessageContaining("Column myobj['a'] unknown");

        // Disabling error on unknown object key allows to use subscript without any error even that it is untyped
        executor.getSessionSettings().setErrorOnUnknownObjectKey(false);
        var analyzed = executor.analyze("SELECT myobj['a'] FROM (SELECT '{\"a\":1}'::OBJECT as myobj) t");
        assertThat(analyzed.outputs().getFirst()).isFunction("subscript", DataTypes.UNDEFINED);
        // Same for references
        analyzed = executor.analyze("SELECT myobj['a'] FROM (SELECT js::OBJECT as myobj FROM t1) t");
        assertThat(analyzed.outputs().getFirst()).isFunction("subscript", DataTypes.UNDEFINED);

        // DYNAMIC object cast with inner types always work
        executor.getSessionSettings().setErrorOnUnknownObjectKey(true);
        analyzed = executor.analyze("SELECT myobj['a'] FROM (SELECT '{\"a\":1}'::OBJECT AS (a int) as myobj) t");
        assertThat(analyzed.outputs().getFirst()).isFunction("subscript", DataTypes.INTEGER);
        // Same for references
        analyzed = executor.analyze("SELECT myobj['a'] FROM (SELECT js::OBJECT AS (a int) as myobj FROM t1) t");
        assertThat(analyzed.outputs().getFirst()).isFunction("subscript", DataTypes.INTEGER);

        // IGNORE object cast always results in an untyped object, but works with subscript
        analyzed = executor.analyze("SELECT myobj['a'] FROM (SELECT '{\"a\":1}'::OBJECT(IGNORED) as myobj) t");
        assertThat(analyzed.outputs().getFirst()).isFunction("subscript", DataTypes.UNDEFINED);
        // Same for references
        analyzed = executor.analyze("SELECT myobj['a'] FROM (SELECT js::OBJECT(IGNORED) as myobj FROM t1) t");
        assertThat(analyzed.outputs().getFirst()).isFunction("subscript", DataTypes.UNDEFINED);
    }
}
