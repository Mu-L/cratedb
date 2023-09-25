/*
 * Licensed to Crate.io GmbH ("Crate") under one or more contributor
 * license agreements.  See the NOTICE file distributed with this work for
 * additional information regarding copyright ownership.  Crate licenses
 * this file to you under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.  You may
 * obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
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

package io.crate.planner.optimizer.rule;

import static io.crate.common.collections.Iterables.getOnlyElement;
import static org.assertj.core.api.Assertions.assertThat;
import static io.crate.testing.Asserts.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import java.util.function.Function;

import org.junit.Before;
import org.junit.Test;

import io.crate.analyze.WhereClause;
import io.crate.analyze.relations.DocTableRelation;
import io.crate.expression.symbol.Symbol;
import io.crate.metadata.CoordinatorTxnCtx;
import io.crate.metadata.doc.DocTableInfo;
import io.crate.planner.operators.Collect;
import io.crate.planner.operators.Filter;
import io.crate.planner.operators.JoinPlan;
import io.crate.planner.operators.LogicalPlan;
import io.crate.planner.optimizer.joinorder.JoinGraph;
import io.crate.planner.optimizer.matcher.Captures;
import io.crate.planner.optimizer.matcher.Match;
import io.crate.sql.tree.JoinType;
import io.crate.test.integration.CrateDummyClusterServiceUnitTest;
import io.crate.testing.SQLExecutor;

public class EliminateCrossJoinTest extends CrateDummyClusterServiceUnitTest {

    private SQLExecutor e;
    private Symbol x;
    private Symbol y;
    private Symbol z;
    private Symbol w;
    private Collect a;
    private Collect b;
    private Collect c;
    private Collect d;

    @Before
    public void prepare() throws Exception {
        e = SQLExecutor.builder(clusterService)
            .addTable("create table a (x int)")
            .addTable("create table b (y int)")
            .addTable("create table c (z int)")
            .addTable("create table d (w int)")
            .build();

        DocTableInfo aDoc = e.resolveTableInfo("a");
        DocTableInfo bDoc = e.resolveTableInfo("b");
        DocTableInfo cDoc = e.resolveTableInfo("c");
        DocTableInfo dDoc = e.resolveTableInfo("d");

        x = e.asSymbol("x");
        y = e.asSymbol("y");
        z = e.asSymbol("z");
        w = e.asSymbol("w");

        a = new Collect(new DocTableRelation(aDoc), List.of(x), WhereClause.MATCH_ALL);
        b = new Collect(new DocTableRelation(bDoc), List.of(y), WhereClause.MATCH_ALL);
        c = new Collect(new DocTableRelation(cDoc), List.of(z), WhereClause.MATCH_ALL);
        d = new Collect(new DocTableRelation(dDoc), List.of(w), WhereClause.MATCH_ALL);
    }

    @Test
    public void test_build_graph_from_a_single_join_reorder_and_rebuild_to_logical_plan() throws Exception {
        var joinCondition = e.asSymbol("a.x = b.y");
        var join = new JoinPlan(a, b, JoinType.INNER, joinCondition);

        assertThat(join).hasOperators(
            "Join[INNER | (x = y)]",
            "  ├ Collect[doc.a | [x] | true]",
            "  └ Collect[doc.b | [y] | true]"
        );

        JoinGraph joinGraph = JoinGraph.create(join, Function.identity());
        assertThat(joinGraph.nodes()).containsExactly(a, b);
        assertThat(joinGraph.edges()).hasSize(2);

        var edges = joinGraph.edges().get(a);
        assertThat(edges).hasSize(1);
        var edge = getOnlyElement(edges);
        assertThat(edge.to()).isEqualTo(b);
        assertThat(edge.left()).isEqualTo(x);
        assertThat(edge.right()).isEqualTo(y);

        edges = joinGraph.edges().get(b);
        assertThat(edges).hasSize(1);
        edge = getOnlyElement(edges);
        assertThat(edge.to()).isEqualTo(a);
        assertThat(edge.left()).isEqualTo(x);
        assertThat(edge.right()).isEqualTo(y);

        var reordered = EliminateCrossJoin.reorder(joinGraph, List.of(b, a));
        assertThat(reordered).hasOperators(
            "Join[INNER | (x = y)]",
            "  ├ Collect[doc.b | [y] | true]",
            "  └ Collect[doc.a | [x] | true]"
        );
    }

    @Test
    public void test_build_graph_from_a_double_nested_join_reorder_and_rebuild_to_logical_plan() throws Exception {
        Symbol firstJoinCondition = e.asSymbol("a.x = b.y");
        var firstJoin = new JoinPlan(a, b, JoinType.INNER, firstJoinCondition);
        Symbol secondJoinCondition = e.asSymbol("b.y = c.z");
        var join = new JoinPlan(firstJoin, c, JoinType.INNER, secondJoinCondition);

        assertThat(join).hasOperators(
            "Join[INNER | (y = z)]",
            "  ├ Join[INNER | (x = y)]",
            "  │  ├ Collect[doc.a | [x] | true]",
            "  │  └ Collect[doc.b | [y] | true]",
            "  └ Collect[doc.c | [z] | true]"
        );

        JoinGraph joinGraph = JoinGraph.create(join, Function.identity());
        // This builds the following graph:
        // [a]--[a.x = b.y]--[b]--[b.y = c.z]--[c]
        assertThat(joinGraph.nodes()).containsExactly(a, b, c);

        var edges = joinGraph.edges().get(a);
        assertThat(edges).hasSize(1);
        // `a.x = b.y` creates an edge from a to b
        assertThat(edges).contains(
            new JoinGraph.Edge(b, x, y)
        );

        // `b.y = c.z` creates an edge from b to c
        edges = joinGraph.edges().get(b);
        assertThat(edges).hasSize(2);
        assertThat(edges).contains(
            new JoinGraph.Edge(a, x, y),
            new JoinGraph.Edge(c, y, z)
        );

        var reordered = EliminateCrossJoin.reorder(joinGraph, List.of(c, b, a));
        assertThat(reordered).hasOperators(
            "Join[INNER | (x = y)]",
            "  ├ Join[INNER | (y = z)]",
            "  │  ├ Collect[doc.c | [z] | true]",
            "  │  └ Collect[doc.b | [y] | true]",
            "  └ Collect[doc.a | [x] | true]"
        );

        List<LogicalPlan> invalidOrder = List.of(a, c, b);
        assertThatThrownBy(() -> EliminateCrossJoin.reorder(joinGraph, invalidOrder))
            .hasMessage("JoinPlan cannot be built with the provided order [doc.a, doc.c, doc.b]");
    }

    @Test
    public void test_build_graph_from_a_triple_nested_join_reorder_and_rebuild_to_logical_plan() throws Exception {
        Symbol firstJoinCondition = e.asSymbol("a.x = b.y");
        var firstJoin = new JoinPlan(a, b, JoinType.INNER, firstJoinCondition);

        Symbol secondJoinCondition = e.asSymbol("a.x = c.z");
        var secondJoin = new JoinPlan(firstJoin, c, JoinType.INNER, secondJoinCondition);

        Symbol topJoinCondition = e.asSymbol("b.y = d.w");
        var topJoin = new JoinPlan(secondJoin, d, JoinType.INNER, topJoinCondition);

        assertThat(topJoin).isEqualTo(
            "Join[INNER | (y = w)]\n" +
            "  ├ Join[INNER | (x = z)]\n" +
            "  │  ├ Join[INNER | (x = y)]\n" +
            "  │  │  ├ Collect[doc.a | [x] | true]\n" +
            "  │  │  └ Collect[doc.b | [y] | true]\n" +
            "  │  └ Collect[doc.c | [z] | true]\n" +
            "  └ Collect[doc.d | [w] | true]"
        );

        JoinGraph joinGraph = JoinGraph.create(topJoin, Function.identity());

        assertThat(EliminateCrossJoin.reorder(joinGraph, List.of(a, c, b, d))).isEqualTo(
            "Join[INNER | (y = w)]\n" +
            "  ├ Join[INNER | (x = y)]\n" +
            "  │  ├ Join[INNER | (x = z)]\n" +
            "  │  │  ├ Collect[doc.a | [x] | true]\n" +
            "  │  │  └ Collect[doc.c | [z] | true]\n" +
            "  │  └ Collect[doc.b | [y] | true]\n" +
            "  └ Collect[doc.d | [w] | true]"
        );

        assertThat(EliminateCrossJoin.reorder(joinGraph, List.of(b, d, a, c))).isEqualTo(
            "Join[INNER | (x = z)]\n" +
            "  ├ Join[INNER | (x = y)]\n" +
            "  │  ├ Join[INNER | (y = w)]\n" +
            "  │  │  ├ Collect[doc.b | [y] | true]\n" +
            "  │  │  └ Collect[doc.d | [w] | true]\n" +
            "  │  └ Collect[doc.a | [x] | true]\n" +
            "  └ Collect[doc.c | [z] | true]"
        );
    }

    @Test
    public void test_build_graph_from_a_nested_join_with_filter_and_rebuild_to_logical_plan() throws Exception {
        Symbol firstJoinCondition = e.asSymbol("a.x = b.y");
        var firstJoin = new JoinPlan(a, b, JoinType.INNER, firstJoinCondition);
        Symbol secondJoinCondition = e.asSymbol("b.y = c.z");
        var join = new JoinPlan(firstJoin, c, JoinType.INNER, secondJoinCondition);
        var filter = new Filter(join, e.asSymbol("a.x > 1"));

        assertThat(filter).hasOperators(
            "Filter[(x > 1)]",
            "  └ Join[INNER | (y = z)]",
            "    ├ Join[INNER | (x = y)]",
            "    │  ├ Collect[doc.a | [x] | true]",
            "    │  └ Collect[doc.b | [y] | true]",
            "    └ Collect[doc.c | [z] | true]"
        );

        JoinGraph joinGraph = JoinGraph.create(filter, Function.identity());

        assertThat(EliminateCrossJoin.reorder(joinGraph, List.of(c, b, a))).hasOperators(
            "Filter[(x > 1)]",
            "  └ Join[INNER | (x = y)]",
            "    ├ Join[INNER | (y = z)]",
            "    │  ├ Collect[doc.c | [z] | true]",
            "    │  └ Collect[doc.b | [y] | true]",
            "    └ Collect[doc.a | [x] | true]"
        );

        var secondFilter = new Filter(filter, e.asSymbol("b.y < 10"));

        joinGraph = JoinGraph.create(secondFilter, Function.identity());

        assertThat(EliminateCrossJoin.reorder(joinGraph, List.of(c, b, a))).hasOperators(
            "Filter[(y < 10)]",
            "  └ Filter[(x > 1)]",
            "    └ Join[INNER | (x = y)]",
            "      ├ Join[INNER | (y = z)]",
            "      │  ├ Collect[doc.c | [z] | true]",
            "      │  └ Collect[doc.b | [y] | true]",
            "      └ Collect[doc.a | [x] | true]"
        );
    }

    public void test_eliminate_cross_join() throws Exception {
        var firstJoin = new JoinPlan(a, b, JoinType.CROSS, null);
        Symbol joinCondition = e.asSymbol("c.z = a.x AND c.z = b.y");
        var join = new JoinPlan(firstJoin, c, JoinType.INNER, joinCondition);

        assertThat(join).hasOperators(
            "Join[INNER | ((z = x) AND (z = y))]",
            "  ├ Join[CROSS]",
            "  │  ├ Collect[doc.a | [x] | true]",
            "  │  └ Collect[doc.b | [y] | true]",
            "  └ Collect[doc.c | [z] | true]"
        );

        var joinGraph = JoinGraph.create(join, Function.identity());
        var originalOrder = joinGraph.nodes();
        assertThat(originalOrder).isEqualTo(List.of(a, b, c));
        var newOrder = EliminateCrossJoin.eliminateCrossJoin(joinGraph);
        assertThat(newOrder).isEqualTo(List.of(a, c, b));

        var rule = new EliminateCrossJoin();
        Match<JoinPlan> match = rule.pattern().accept(join, Captures.empty());

        assertThat(match.isPresent()).isTrue();
        assertThat(match.value()).isEqualTo(join);

        var result = rule.apply(match.value(),
                                match.captures(),
                                e.planStats(),
                                CoordinatorTxnCtx.systemTransactionContext(),
                                e.nodeCtx,
                                Function.identity());

        assertThat(result).hasOperators(
            "Eval[x, y, z]",
            "  └ Join[INNER | (z = y)]",
            "    ├ Join[INNER | (z = x)]",
            "    │  ├ Collect[doc.a | [x] | true]",
            "    │  └ Collect[doc.c | [z] | true]",
            "    └ Collect[doc.b | [y] | true]"
        );
    }

    public void test_do_not_reorder_with_outer_joins() throws Exception {
        var firstJoin = new JoinPlan(a, b, JoinType.CROSS, null);
        Symbol joinCondition = e.asSymbol("c.z = a.x AND c.z = b.y");
        var join = new JoinPlan(firstJoin, c, JoinType.LEFT, joinCondition);

        assertThat(join).isEqualTo(
            "Join[LEFT | ((z = x) AND (z = y))]\n" +
            "  ├ Join[CROSS]\n" +
            "  │  ├ Collect[doc.a | [x] | true]\n" +
            "  │  └ Collect[doc.b | [y] | true]\n" +
            "  └ Collect[doc.c | [z] | true]"
        );

        var rule = new EliminateCrossJoin();
        Match<JoinPlan> match = rule.pattern().accept(join, Captures.empty());

        assertThat(match.isPresent()).isTrue();
        assertThat(match.value()).isEqualTo(join);

        var result = rule.apply(match.value(),
                                match.captures(),
                                e.planStats(),
                                CoordinatorTxnCtx.systemTransactionContext(),
                                e.nodeCtx,
                                Function.identity());

        assertThat(result).isNull();

        joinCondition = e.asSymbol("a.x = b.y");
        firstJoin = new JoinPlan(a, b, JoinType.LEFT, joinCondition);
        join = new JoinPlan(firstJoin, c, JoinType.CROSS, null);

        match = rule.pattern().accept(join, Captures.empty());

        assertThat(match.isPresent()).isTrue();
        assertThat(match.value()).isEqualTo(join);

        result = rule.apply(match.value(),
                            match.captures(),
                            e.planStats(),
                            CoordinatorTxnCtx.systemTransactionContext(),
                            e.nodeCtx,
                            Function.identity());

        assertThat(result).isNull();
    }

    public void test_do_not_reorder_without_a_crossjoin() throws Exception {
        var firstJoin = new JoinPlan(a, b, JoinType.LEFT, e.asSymbol("a.x = b.y"));
        var secondJoin = new JoinPlan(firstJoin, c, JoinType.INNER, e.asSymbol("a.x = b.y"));

        assertThat(secondJoin).isEqualTo(
            "Join[INNER | (x = y)]\n" +
            "  ├ Join[LEFT | (x = y)]\n" +
            "  │  ├ Collect[doc.a | [x] | true]\n" +
            "  │  └ Collect[doc.b | [y] | true]\n" +
            "  └ Collect[doc.c | [z] | true]"
        );

        var rule = new EliminateCrossJoin();
        Match<JoinPlan> match = rule.pattern().accept(secondJoin, Captures.empty());

        assertThat(match.isPresent()).isTrue();
        assertThat(match.value()).isEqualTo(secondJoin);

        var result = rule.apply(match.value(),
                                match.captures(),
                                e.planStats(),
                                CoordinatorTxnCtx.systemTransactionContext(),
                                e.nodeCtx,
                                Function.identity());

        assertThat(result).isNull();
    }

}
