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

package io.crate.testing;


import static io.crate.testing.Asserts.assertThat;
import static org.assertj.core.api.Assertions.assertThat;

import org.assertj.core.api.AbstractAssert;

import io.crate.execution.dsl.projection.FilterProjection;
import io.crate.execution.dsl.projection.LimitAndOffsetProjection;
import io.crate.execution.dsl.projection.LimitDistinctProjection;
import io.crate.execution.dsl.projection.Projection;

public final class ProjectionAssert extends AbstractAssert<ProjectionAssert, Projection> {

    public ProjectionAssert(Projection actual) {
        super(actual, ProjectionAssert.class);
    }

    public ProjectionAssert isLimitAndOffset(int expectedLimit, int expectedOffset) {
        isNotNull();
        isExactlyInstanceOf(LimitAndOffsetProjection.class);
        assertThat(((LimitAndOffsetProjection) actual).limit()).isEqualTo(expectedLimit);
        assertThat(((LimitAndOffsetProjection) actual).offset()).isEqualTo(expectedOffset);
        return this;
    }

    public ProjectionAssert isLimitDistinct(int expectedLimit) {
        isNotNull();
        isExactlyInstanceOf(LimitDistinctProjection.class);
        assertThat(((LimitDistinctProjection) actual).limit()).isEqualTo(expectedLimit);
        return this;
    }

    public ProjectionAssert isFilter(String sqlQuery) {
        isNotNull();
        isExactlyInstanceOf(FilterProjection.class);
        assertThat(((FilterProjection) actual).query()).isSQL(sqlQuery);
        return this;
    }
}
