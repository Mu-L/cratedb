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

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.ArrayList;

import org.junit.Test;

public class FloatVectorTypeTest extends DataTypeTestCase<float[]> {

    @Override
    protected DataDef<float[]> getDataDef() {
        return DataDef.fromType(new FloatVectorType(4));
    }

    @Override
    protected boolean supportsArrays() {
        return false;
    }

    @Test
    public void test_cannot_insert_nulls_into_float_vector() {
        var floatVectorType = new FloatVectorType(3);
        var insertValues = new ArrayList<>(3); // List.of() doesn't allow nulls
        insertValues.add(1.1);
        insertValues.add(null);
        insertValues.add(2.2);
        assertThatThrownBy(() -> floatVectorType.sanitizeValue(insertValues))
            .isExactlyInstanceOf(UnsupportedOperationException.class)
            .hasMessage("null values are not allowed for float_vector");
    }

    @Test
    public void test_cannot_create_float_vector_type_exceeding_max_length() {
        assertThatThrownBy(() -> new FloatVectorType(2049))
            .isExactlyInstanceOf(IllegalArgumentException.class)
            .hasMessage("Float vector type's length cannot exceed 2048");
    }
}
