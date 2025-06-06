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

package io.crate.expression;

import static io.crate.testing.TestingHelpers.refInfo;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import io.crate.analyze.relations.AnalyzedRelation;
import io.crate.analyze.relations.DocTableRelation;
import io.crate.data.Input;
import io.crate.data.Row;
import io.crate.data.RowN;
import io.crate.execution.engine.aggregation.AggregationContext;
import io.crate.execution.engine.collect.CollectExpression;
import io.crate.expression.scalar.arithmetic.ArithmeticFunctions;
import io.crate.expression.symbol.Aggregation;
import io.crate.expression.symbol.Function;
import io.crate.expression.symbol.InputColumn;
import io.crate.expression.symbol.Literal;
import io.crate.expression.symbol.Symbol;
import io.crate.metadata.CoordinatorTxnCtx;
import io.crate.metadata.FunctionImplementation;
import io.crate.metadata.FunctionType;
import io.crate.metadata.Reference;
import io.crate.metadata.RelationName;
import io.crate.metadata.RowGranularity;
import io.crate.metadata.Scalar;
import io.crate.metadata.Scalar.Feature;
import io.crate.metadata.TransactionContext;
import io.crate.metadata.functions.Signature;
import io.crate.test.integration.CrateDummyClusterServiceUnitTest;
import io.crate.testing.SqlExpressions;
import io.crate.testing.T3;
import io.crate.types.DataTypes;

public class InputFactoryTest extends CrateDummyClusterServiceUnitTest {

    private SqlExpressions expressions;
    private InputFactory factory;
    private TransactionContext txnCtx = CoordinatorTxnCtx.systemTransactionContext();
    private Function add = new Function(
            Signature.builder(ArithmeticFunctions.Names.ADD, FunctionType.SCALAR)
                    .argumentTypes(DataTypes.INTEGER.getTypeSignature(),
                            DataTypes.INTEGER.getTypeSignature())
                    .returnType(DataTypes.INTEGER.getTypeSignature())
                    .features(Feature.DETERMINISTIC, Feature.COMPARISON_REPLACEMENT, Scalar.Feature.STRICTNULL)
                    .build(),
            List.of(new InputColumn(1, DataTypes.INTEGER), Literal.of(10)),
            DataTypes.INTEGER
    );

    @Before
    public void prepare() throws Exception {
        Map<RelationName, AnalyzedRelation> sources = T3.sources(List.of(T3.T1), clusterService);

        DocTableRelation tr1 = (DocTableRelation) sources.get(T3.T1);
        expressions = new SqlExpressions(sources, tr1);
        factory = new InputFactory(expressions.nodeCtx);
    }

    @Test
    public void testAggregationSymbolsInputReuse() throws Exception {
        Function countX = (Function) expressions.asSymbol("count(x)");
        Function avgX = (Function) expressions.asSymbol("avg(x)");

        List<Symbol> aggregations = Arrays.asList(
            new Aggregation(countX.signature(),
                            countX.signature().getReturnType().createType(),
                            List.of(new InputColumn(0))),
            new Aggregation(avgX.signature(),
                            avgX.signature().getReturnType().createType(),
                            List.of(new InputColumn(0)))
        );

        InputFactory.Context<CollectExpression<Row, ?>> ctx = factory.ctxForAggregations(txnCtx);
        ctx.add(aggregations);
        List<AggregationContext> aggregationContexts = ctx.aggregations();

        Input<?> inputCount = aggregationContexts.get(0).inputs()[0];
        Input<?> inputAverage = aggregationContexts.get(1).inputs()[0];

        assertThat(inputAverage).isSameAs(inputCount);
    }

    @Test
    public void testProcessGroupByProjectionSymbols() throws Exception {
        // select x, y * 2 ... group by x, y * 2

        // keys: [ in(0), in(1) + 10 ]
        List<Symbol> keys = Arrays.asList(new InputColumn(0, DataTypes.LONG), add);

        InputFactory.Context<CollectExpression<Row, ?>> ctx = factory.ctxForAggregations(txnCtx);
        ctx.add(keys);
        ArrayList<CollectExpression<Row, ?>> expressions = new ArrayList<>(ctx.expressions());
        assertThat(expressions).hasSize(2);

        // keyExpressions: [ in0, in1 ]

        RowN row = new RowN(1L, 2L);
        for (CollectExpression<Row, ?> expression : expressions) {
            expression.setNextRow(row);
        }
        assertThat(expressions.get(0).value()).isEqualTo(1L);
        assertThat(expressions.get(1).value()).isEqualTo(2L); // raw input value

        // inputs: [ x, add ]
        List<Input<?>> inputs = ctx.topLevelInputs();

        assertThat(inputs).hasSize(2);
        assertThat(inputs.get(0).value()).isEqualTo(1L);
        assertThat(inputs.get(1).value()).isEqualTo(12);  // + 10
    }

    @Test
    public void testProcessGroupByProjectionSymbolsAggregation() throws Exception {
        // select count(x), x, y * 2 ... group by x, y * 2

        // keys: [ in(0), in(1) + 10 ]
        List<Symbol> keys = Arrays.asList(new InputColumn(0, DataTypes.LONG), add);

        Function countX = (Function) expressions.asSymbol("count(x)");

        // values: [ count(in(0)) ]
        List<Aggregation> values = List.of(new Aggregation(
            countX.signature(),
            countX.valueType(),
            List.of(new InputColumn(0))
        ));

        InputFactory.Context<CollectExpression<Row, ?>> ctx = factory.ctxForAggregations(txnCtx);
        ctx.add(keys);

        // inputs: [ x, add ]
        List<Input<?>> keyInputs = ctx.topLevelInputs();

        ctx.add(values);

        List<AggregationContext> aggregations = ctx.aggregations();
        assertThat(aggregations).hasSize(1);

        // collectExpressions: [ in0, in1 ]
        List<CollectExpression<Row, ?>> expressions = new ArrayList<>(ctx.expressions());
        assertThat(expressions).hasSize(2);

        List<Input<?>> allInputs = ctx.topLevelInputs();
        assertThat(allInputs).hasSize(2); // only 2 because count is no input

        RowN row = new RowN(1L, 2L);
        for (CollectExpression<Row, ?> expression : expressions) {
            expression.setNextRow(row);
        }
        assertThat(expressions.get(0).value()).isEqualTo(1L);
        assertThat(expressions.get(1).value()).isEqualTo(2L); // raw input value

        assertThat(keyInputs).hasSize(2);
        assertThat(keyInputs.get(0).value()).isEqualTo(1L);
        assertThat(keyInputs.get(1).value()).isEqualTo(12);  // 2 + 10
    }

    @Test
    public void testCompiled() throws Exception {
        Function function = (Function) expressions.normalize(expressions.asSymbol("a like 'f%'"));
        InputFactory.Context<Input<?>> ctx = factory.ctxForRefs(txnCtx, _ -> Literal.of("foo"));
        Input<?> input = ctx.add(function);

        FunctionExpression<?, ?> expression = (FunctionExpression<?, ?>) input;
        java.lang.reflect.Field f = FunctionExpression.class.getDeclaredField("scalar");
        f.setAccessible(true);
        FunctionImplementation impl = (FunctionImplementation) f.get(expression);
        assertThat(impl.signature()).isEqualTo(function.signature());

        FunctionImplementation uncompiled = expressions.nodeCtx.functions().getQualified(function);
        assertThat(uncompiled).isNotSameAs(impl);
    }

    @Test
    public void testSameReferenceResultsInSameExpressionInstance() {
        Symbol symbol = expressions.normalize(expressions.asSymbol("a"));
        InputFactory.Context<Input<?>> ctx = factory.ctxForRefs(txnCtx, i -> Literal.of("foo"));
        Input<?> input1 = ctx.add(symbol);
        Input<?> input2 = ctx.add(symbol);

        assertThat(input1).isSameAs(input2);
    }

    @Test
    public void test_missing_reference() throws Exception {
        InputFactory.Context<Input<?>> ctx = factory.ctxForRefs(txnCtx, _ -> null);

        Reference refInfo = refInfo("doc.tbl.id", DataTypes.INTEGER, RowGranularity.SHARD);
        assertThatThrownBy(() -> ctx.add(refInfo))
            .isExactlyInstanceOf(IllegalArgumentException.class)
            .hasMessage("Column implementation not found for: id");

        Reference sysRefInfo = refInfo("sys.shards.id", DataTypes.INTEGER, RowGranularity.SHARD);
        assertThatThrownBy(() -> ctx.add(sysRefInfo))
            .isExactlyInstanceOf(IllegalArgumentException.class)
            .hasMessage("Column implementation not found for: id. This can happen in mixed clusters when using `SELECT *`; Declare the column list explicitly instead");
    }
}
