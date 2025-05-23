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

package io.crate.expression.scalar;

import static io.crate.testing.Asserts.isLiteral;
import static io.crate.testing.Asserts.isNull;
import static io.crate.testing.Asserts.isObjectLiteral;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import java.util.Map;

import org.junit.Test;

import io.crate.exceptions.UnsupportedFunctionException;
import io.crate.types.DataTypes;

public class ConcatFunctionTest extends ScalarTestCase {

    @Test
    public void testOneArgument() {
        assertNormalize("concat('foo')", isLiteral("foo"));
    }

    @Test
    public void testArgumentThatHasNoStringRepr() {
        assertThatThrownBy(() -> assertNormalize("concat('foo', [1])", isNull()))
            .isExactlyInstanceOf(UnsupportedFunctionException.class)
            .hasMessageStartingWith("Invalid arguments in: concat('foo', [1]) with (text, integer_array).");
    }


    @Test
    public void testNormalizeWithNulls() {
        assertNormalize("concat(null, null)", isLiteral(""));
        assertNormalize("concat(null, 'foo')", isLiteral("foo"));
        assertNormalize("concat('foo', null)", isLiteral("foo"));

        assertNormalize("concat(5, null)", isLiteral("5"));
    }

    @Test
    public void testTwoStrings() {
        assertNormalize("concat('foo', 'bar')", isLiteral("foobar"));
    }

    @Test
    public void testManyStrings() {
        assertNormalize("concat('foo', null, '_', null, 'testing', null, 'is_boring')",
            isLiteral("foo_testingis_boring"));
    }

    @Test
    public void testStringAndNumber() {
        assertNormalize("concat('foo', 3)", isLiteral("foo3"));
    }

    @Test
    public void testNumberAndString() {
        assertNormalize("concat(3, 2, 'foo')", isLiteral("32foo"));
    }

    @Test
    public void testTwoArrays() throws Exception {
        assertNormalize("concat([1, 2], [2, 3])", isLiteral(List.of(1, 2, 2, 3)));
    }

    @Test
    public void testArrayWithAUndefinedInnerType() throws Exception {
        assertNormalize("concat([], [1, 2])", isLiteral(List.of(1, 2)));
    }

    @Test
    public void testTwoArraysOfIncompatibleInnerTypes() {
        assertThatThrownBy(() -> assertNormalize("concat([1, 2], [[1, 2]])", isNull()))
            .isExactlyInstanceOf(UnsupportedFunctionException.class)
            .hasMessageStartingWith(
                "Invalid arguments in: concat([1, 2], [[1, 2]]) with (integer_array, integer_array_array).");
    }

    @Test
    public void testTwoArraysOfUndefinedTypes() throws Exception {
        assertNormalize("concat([], [])", isLiteral(List.of()));
    }

    @Test
    public void testEvaluate() throws Exception {
        assertEvaluate("concat([1::bigint], [2, 3])", List.of(1L, 2L, 3L));
    }

    @Test
    public void test_two_string_arguments_result_in_special_scalar() {
        var func = getFunction(ConcatFunction.NAME, List.of(DataTypes.STRING, DataTypes.STRING));
        assertThat(func).isExactlyInstanceOf(ConcatFunction.StringConcatFunction.class);
    }

    @Test
    public void test_two_objects() {
        assertNormalize("concat({a=1},{a=2,b=2})", isObjectLiteral(Map.of("a",2,"b",2)));
    }

    @Test
    public void test_concat_operator_with_null_literals() {
        assertNormalize("null || null", isLiteral(null));
        assertNormalize("null || 'foo'", isLiteral(null));
        assertNormalize("'foo' || null", isLiteral(null));

        assertNormalize("[1] || null", isLiteral(List.of(1)));
        assertNormalize("null || [1]", isLiteral(List.of(1)));
    }

    public void test_concat_operator_with_strings() {
        assertNormalize("'foo' || 'bar'", isLiteral("foobar"));
    }

    public void test_concat_operator_with_arrays() {
        assertNormalize("[] || [1]", isLiteral(List.of(1)));
    }

    public void test_concat_operator_with_objects() {
        assertNormalize("{a=1} || {a=2,b=2}", isObjectLiteral(Map.of("a",2,"b",2)));
    }

    @Test
    public void test_concat_operator_with_array_and_element() {
        assertEvaluate("[1] || 2", List.of(1, 2));
    }

    @Test
    public void test_concat_operator_with_element_and_array() {
        assertEvaluate("1 || [2]", List.of(1, 2));
    }
}
