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

package io.crate.planner.operators;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.Before;
import org.junit.Test;

import io.crate.expression.symbol.Symbol;
import io.crate.test.integration.CrateDummyClusterServiceUnitTest;
import io.crate.testing.SqlExpressions;
import io.crate.testing.T3;

public class EquiJoinDetectorTest extends CrateDummyClusterServiceUnitTest {

    private SqlExpressions sqlExpressions;

    @Before
    public void prepare() throws Exception {
        sqlExpressions = new SqlExpressions(T3.sources(clusterService));
    }

    @Test
    public void testPossibleOnInnerContainingEqCondition() {
        Symbol joinCondition = sqlExpressions.asSymbol("t1.x = t2.y");
        assertThat(EquiJoinDetector.isEquiJoin(joinCondition)).isTrue();
    }

    @Test
    public void test_equality_condition_inside_cast() {
        Symbol joinCondition = sqlExpressions.asSymbol("CAST(CAST(t1.a = t2.b AS STRING) AS BOOLEAN)");
        assertThat(EquiJoinDetector.isEquiJoin(joinCondition)).isTrue();
    }

    @Test
    public void testPossibleOnInnerContainingEqAndAnyCondition() {
        Symbol joinCondition = sqlExpressions.asSymbol("t1.x > t2.y and t1.a = t2.b and not(t1.i = t2.i)");
        assertThat(EquiJoinDetector.isEquiJoin(joinCondition)).isTrue();
    }

    @Test
    public void testNotPossibleOnInnerWithoutAnyEqCondition() {
        Symbol joinCondition = sqlExpressions.asSymbol("t1.x > t2.y and t1.a > t2.b");
        assertThat(EquiJoinDetector.isEquiJoin(joinCondition)).isFalse();
    }

    @Test
    public void testPossibleOnInnerWithEqAndScalarOnOneRelation() {
        Symbol joinCondition = sqlExpressions.asSymbol("t1.x + t1.i = t2.b");
        assertThat(EquiJoinDetector.isEquiJoin(joinCondition)).isTrue();
    }

    @Test
    public void testNotPossibleOnInnerWithEqAndScalarOnMultipleRelations() {
        Symbol joinCondition = sqlExpressions.asSymbol("t1.x + t2.y = 4");
        assertThat(EquiJoinDetector.isEquiJoin(joinCondition)).isFalse();
    }

    @Test
    public void testNotPossibleOnInnerContainingEqOrAnyCondition() {
        Symbol joinCondition = sqlExpressions.asSymbol("t1.x = t2.y and t1.a = t2.b or t1.i = t2.i");
        assertThat(EquiJoinDetector.isEquiJoin(joinCondition)).isFalse();

        joinCondition = sqlExpressions.asSymbol("(t1.a = t2.b or t1.x = t2.y) and t1.i = t2.i");
        assertThat(EquiJoinDetector.isEquiJoin(joinCondition)).isFalse();
    }

    @Test
    public void testNotPossibleOnEqWithoutRelationFieldsOnBothSides() {
        Symbol joinCondition = sqlExpressions.asSymbol("t1.x = 4");
        assertThat(EquiJoinDetector.isEquiJoin(joinCondition)).isFalse();
    }

    @Test
    public void testNotPossibleOnNotWrappingEq() {
        Symbol joinCondition = sqlExpressions.asSymbol("NOT (t1.a = t2.b)");
        assertThat(EquiJoinDetector.isEquiJoin(joinCondition)).isFalse();
    }

    @Test
    public void test_not_hash_join_possible_if_join_condition_refers_to_columns_from_a_single_relation() {
        Symbol joinCondition = sqlExpressions.asSymbol("t1.a + t1.a = t1.a + t1.a");
        assertThat(EquiJoinDetector.isEquiJoin(joinCondition)).isFalse();

        joinCondition = sqlExpressions.asSymbol("t1.x = t1.i");
        assertThat(EquiJoinDetector.isEquiJoin(joinCondition)).isFalse();
    }

    // tracks a bug: https://github.com/crate/crate/issues/15613
    @Test
    public void test_equality_expression_followed_by_case_expression() {
        Symbol joinCondition = sqlExpressions.asSymbol("t1.a = t1.a AND CASE 1 WHEN t1.a THEN false ELSE t2.b in (t2.b) END");
        assertThat(EquiJoinDetector.isEquiJoin(joinCondition)).isFalse();
    }

    // tracks a bug: https://github.com/crate/crate/issues/17380
    @Test
    public void test_case_expression_with_nested_equality() {
        Symbol joinCondition = sqlExpressions.asSymbol("CASE WHEN t1.a = t2.b THEN t1.a ELSE t2.b END");
        assertThat(EquiJoinDetector.isEquiJoin(joinCondition)).isFalse();
        joinCondition = sqlExpressions.asSymbol("CASE t1.a WHEN t2.b THEN t1.a ELSE t2.b END");
        assertThat(EquiJoinDetector.isEquiJoin(joinCondition)).isFalse();
    }

    // tracks a bug: https://github.com/crate/crate/issues/17380
    @Test
    public void test_if_expression_with_nested_equality() {
        Symbol joinCondition = sqlExpressions.asSymbol("if(t1.a = t2.b, 1, 2)");
        assertThat(EquiJoinDetector.isEquiJoin(joinCondition)).isFalse();
    }

    @Test
    public void test_equality_and_many_relations_in_boolean_join_condition_hash_join_not_possible() {
        // Nested EQ operator.
        Symbol joinCondition = sqlExpressions.asSymbol("(t1.a >= 1) = ((t1.a = t1.a) AND (t2.b <= t2.b))");
        assertThat(EquiJoinDetector.isEquiJoin(joinCondition)).isFalse();

        // Deep nested EQ operator.
        joinCondition = sqlExpressions.asSymbol("(t1.a >= 1) = " +
            " (t2.b < 10 AND ((t2.b < 10) = (t1.a = t1.a + 10) AND (t2.b < 7) = (t1.a = (t1.a - 5))))");
        assertThat(EquiJoinDetector.isEquiJoin(joinCondition)).isFalse();

        // Nested NOT operator
        joinCondition = sqlExpressions.asSymbol("(((t1.a != t1.a) > (t2.b = t2.b)) = t1.a)");
        assertThat(EquiJoinDetector.isEquiJoin(joinCondition)).isFalse();
    }

    @Test
    public void test_inequality_in_boolean_join_condition_hash_join_possible() {
        // Compare column with column
        Symbol joinCondition = sqlExpressions.asSymbol("(t1.a >= 1) = (t2.b <= t2.b)");
        assertThat(EquiJoinDetector.isEquiJoin(joinCondition)).isTrue();

        // Compare column with constant
        joinCondition = sqlExpressions.asSymbol("(t1.a >= 1) = (t2.b < 10)");
        assertThat(EquiJoinDetector.isEquiJoin(joinCondition)).isTrue();

        // Compare with column AND compare with constant.
        joinCondition = sqlExpressions.asSymbol("(t1.a >= 1) = (t2.b <= t2.b AND t2.b < 10)");
        assertThat(EquiJoinDetector.isEquiJoin(joinCondition)).isTrue();
    }

    @Test
    public void test_or_in_boolean_join_condition_hash_join_possible() {
        Symbol joinCondition = sqlExpressions.asSymbol("(t1.a > 1) = (t2.b < 5 OR t2.b > 10)");
        assertThat(EquiJoinDetector.isEquiJoin(joinCondition)).isTrue();
    }
}
