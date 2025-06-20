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

package io.crate.types;

import static com.carrotsearch.randomizedtesting.RandomizedTest.assumeFalse;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import org.elasticsearch.common.io.stream.BytesStreamOutput;
import org.elasticsearch.common.io.stream.StreamInput;
import org.junit.Test;

import io.crate.common.collections.MapBuilder;
import io.crate.exceptions.ConversionException;
import io.crate.sql.tree.ColumnPolicy;
import io.crate.testing.DataTypeTesting;

public class ObjectTypeTest extends DataTypeTestCase<Map<String, Object>> {

    @Override
    protected DataDef<Map<String, Object>> getDataDef() {
        // float vectors will not compare properly so we exclude them here
        DataType<?> innerType
            = DataTypeTesting.randomTypeExcluding(Set.of(FloatVectorType.INSTANCE_ONE, ObjectType.UNTYPED));
        DataType<Map<String, Object>> objectType
            = ObjectType.of(ColumnPolicy.DYNAMIC).setInnerType("x", innerType).build();
        String definition = "OBJECT AS (x " + innerType.getTypeSignature() + ")";
        return new DataDef<>(objectType, definition, DataTypeTesting.getDataGenerator(objectType));
    }

    @Test
    public void testStreamingWithoutInnerTypes() throws IOException {
        ObjectType type = DataTypes.UNTYPED_OBJECT;
        BytesStreamOutput out = new BytesStreamOutput();
        type.writeTo(out);

        StreamInput in = out.bytes().streamInput();
        ObjectType otherType = new ObjectType(in);

        assertThat(otherType.innerTypes()).isEmpty();
    }

    @Test
    public void testStreamingWithEmptyInnerTypes() throws IOException {
        ObjectType type = ObjectType.of(ColumnPolicy.DYNAMIC).build();
        BytesStreamOutput out = new BytesStreamOutput();
        type.writeTo(out);

        StreamInput in = out.bytes().streamInput();
        ObjectType otherType = new ObjectType(in);

        assertThat(otherType.innerTypes()).isEqualTo(type.innerTypes());
    }

    @Test
    public void testStreamingWithInnerTypes() throws IOException {
        ObjectType type = ObjectType.of(ColumnPolicy.DYNAMIC)
            .setInnerType("s", DataTypes.STRING)
            .setInnerType("obj_array", new ArrayType<>(ObjectType.of(ColumnPolicy.DYNAMIC)
                .setInnerType("i", DataTypes.INTEGER)
                .build()))
            .build();
        BytesStreamOutput out = new BytesStreamOutput();
        type.writeTo(out);

        StreamInput in = out.bytes().streamInput();
        ObjectType otherType = new ObjectType(in);

        assertThat(otherType.innerTypes()).isEqualTo(type.innerTypes());
    }

    @Test
    public void testStreamingOfNullValueWithoutInnerTypes() throws IOException {
        ObjectType type = DataTypes.UNTYPED_OBJECT;
        BytesStreamOutput out = new BytesStreamOutput();

        type.writeValueTo(out, null);

        StreamInput in = out.bytes().streamInput();
        ObjectType otherType = DataTypes.UNTYPED_OBJECT;

        Object v = otherType.readValueFrom(in);
        assertThat(v).isNull();
    }

    @Test
    public void testStreamingOfNullValueWithInnerTypes() throws IOException {
        ObjectType type = ObjectType.of(ColumnPolicy.DYNAMIC)
            .setInnerType("s", DataTypes.STRING)
            .setInnerType("obj_array", new ArrayType<>(ObjectType.of(ColumnPolicy.DYNAMIC)
                .setInnerType("i", DataTypes.INTEGER)
                .build()))
            .build();
        BytesStreamOutput out = new BytesStreamOutput();

        type.writeTo(out);
        type.writeValueTo(out, null);

        StreamInput in = out.bytes().streamInput();
        ObjectType otherType = new ObjectType(in);

        Object v = otherType.readValueFrom(in);
        assertThat(v).isNull();
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testStreamingOfValueWithInnerTypes() throws IOException {
        ObjectType type = ObjectType.of(ColumnPolicy.DYNAMIC)
            .setInnerType("s", DataTypes.STRING)
            .setInnerType("obj_array", new ArrayType<>(ObjectType.of(ColumnPolicy.DYNAMIC)
                .setInnerType("i", DataTypes.INTEGER)
                .build()))
            .build();
        BytesStreamOutput out = new BytesStreamOutput();

        HashMap<String, Object> map = new HashMap<>();
        map.put("s", "foo");
        map.put("obj_array", List.of(Map.of("i", 0)));
        type.writeTo(out);
        type.writeValueTo(out, map);

        StreamInput in = out.bytes().streamInput();
        ObjectType otherType = new ObjectType(in);

        Map<String, Object> v = otherType.readValueFrom(in);

        assertThat(v.get("s")).isEqualTo(map.get("s"));
        assertThat((List<Map<?, ?>>) v.get("obj_array")).containsExactly(Map.of("i", 0));
    }

    @Test
    public void testStreamingOfValueWithoutInnerTypes() throws IOException {
        ObjectType type = DataTypes.UNTYPED_OBJECT;
        BytesStreamOutput out = new BytesStreamOutput();

        List<Map<String, Object>> innerArray = List.of(MapBuilder.<String, Object>newMapBuilder()
            .put("i", 1)
            .map()
        );
        HashMap<String, Object> map = new HashMap<>();
        map.put("s", "foo");
        map.put("obj_array", innerArray);
        type.writeTo(out);
        type.writeValueTo(out, map);

        StreamInput in = out.bytes().streamInput();
        ObjectType otherType = new ObjectType(in);

        Map<String, Object> v = otherType.readValueFrom(in);

        assertThat(v.get("s")).isEqualTo(map.get("s"));
        assertThat(Objects.deepEquals(v.get("obj_array"), innerArray)).isTrue();
    }

    @Test
    public void testResolveInnerType() {
        ObjectType type = ObjectType.of(ColumnPolicy.DYNAMIC)
            .setInnerType("s", DataTypes.STRING)
            .setInnerType("inner", ObjectType.of(ColumnPolicy.DYNAMIC)
                .setInnerType("i", DataTypes.INTEGER)
                .build())
            .build();

        assertThat(type.innerType(List.of("s", "inner", "i"))).isEqualTo(DataTypes.UNDEFINED);
        assertThat(type.innerType(List.of("inner", "i"))).isEqualTo(DataTypes.INTEGER);
    }

    @Test
    public void test_inner_type_with_nested_array() {
        ObjectType type = ObjectType.of(ColumnPolicy.DYNAMIC)
            .setInnerType("nested_array", new ArrayType<>(ObjectType.of(ColumnPolicy.DYNAMIC)
                .setInnerType("i", DataTypes.INTEGER)
                .build()))
            .setInnerType("nested_nested_array", new ArrayType<>(new ArrayType<>(ObjectType.of(ColumnPolicy.DYNAMIC)
                .setInnerType("i", DataTypes.INTEGER)
                .build())))
            .build();

        assertThat(type.innerType(List.of("nested_array", "i"))).isEqualTo(new ArrayType<>(DataTypes.INTEGER));
        assertThat(type.innerType(List.of("nested_nested_array", "i"))).isEqualTo(new ArrayType<>(new ArrayType<>(DataTypes.INTEGER)));
    }

    @Test
    public void test_object_type_to_signature_to_object_type_round_trip() {
        var objectType = ObjectType.of(ColumnPolicy.DYNAMIC)
            .setInnerType("inner field", DataTypes.STRING)
            .build();
        assertThat(objectType.getTypeSignature().createType()).isEqualTo(objectType);
    }

    @Test
    public void test_raises_conversion_exception_on_string_parsing_errors() throws Exception {
        assertThatThrownBy(() -> ObjectType.UNTYPED.implicitCast("foo"))
            .isExactlyInstanceOf(ConversionException.class)
            .hasMessage("Cannot cast value `foo` to type `object`");
    }

    @Override
    public void test_reference_resolver_docvalues_off() throws Exception {
        assumeFalse("ObjectType cannot disable column store", true);
    }

    @Override
    public void test_reference_resolver_index_and_docvalues_off() throws Exception {
        assumeFalse("ObjectType cannot disable column store", true);
    }

    @Override
    public void test_reference_resolver_index_off() throws Exception {
        assumeFalse("ObjectType cannot disable index", true);
    }

    @Test
    public void test_value_bytes_accounts_for_deep_objects() throws Exception {
        String str = "a".repeat(1024);
        long valueBytes = ObjectType.UNTYPED.valueBytes(
            Map.of("a",
                Map.of("b",
                    Map.of("c", Map.of("d", str))
                )
            )
        );
        assertThat(valueBytes).isEqualTo(2504L);
    }

    @Test
    public void test_valueForInsert_on_nested_object() {
        Map<String, Object> map = new HashMap<>();
        map.put("c", "abcd");
        var type = ObjectType.of(ColumnPolicy.DYNAMIC)
            .setInnerType("c", CharacterType.of(3))
            .build();
        assertThatThrownBy(() -> type.valueForInsert(map))
            .isExactlyInstanceOf(ConversionException.class)
            .hasMessage("Cannot cast object element `c` with value `abcd` to type `text(3)`");
    }
}
