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

package io.crate.planner.operators;


import org.junit.Test;

import io.crate.test.integration.CrateDummyClusterServiceUnitTest;
import io.crate.testing.SQLExecutor;

public class RenameTest extends CrateDummyClusterServiceUnitTest {

    /**
     * https://github.com/crate/crate/issues/16754
     */
    @Test
    public void test_multiple_symbols() throws Exception {
        var e = SQLExecutor.of(clusterService);
        String stmt = """
             SELECT
                alias1.country,
                MAX(height) FILTER (WHERE height>0) as max_height,
                MAX(prominence) FILTER (WHERE height>0) as max_prominence
            FROM
                sys.summits alias1
            GROUP BY
                alias1.country
            LIMIT 100;
            """;
        LogicalPlan logicalPlan = e.logicalPlan(stmt);
    }
}
