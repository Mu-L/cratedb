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

package io.crate.planner.optimizer;

import static io.crate.analyze.SymbolEvaluator.evaluateWithoutParams;
import static io.crate.testing.TestingHelpers.createNodeContext;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Set;
import java.util.function.Function;

import org.junit.Test;

import io.crate.expression.symbol.Literal;
import io.crate.expression.symbol.Symbol;
import io.crate.metadata.CoordinatorTxnCtx;
import io.crate.metadata.NodeContext;
import io.crate.metadata.SearchPath;
import io.crate.metadata.settings.CoordinatorSessionSettings;
import io.crate.planner.optimizer.rule.MergeFilters;
import io.crate.role.metadata.RolesHelper;

public class OptimizerRuleSessionSettingProviderTest {

    private final NodeContext nodeCtx = createNodeContext();

    private final Function<Symbol, Object> eval = x -> evaluateWithoutParams(
        CoordinatorTxnCtx.systemTransactionContext(),
        nodeCtx,
        x
    );

    @Test
    public void test_optimizer_rule_session_settings() {
        var sessionSetting = LoadedRules.buildRuleSessionSetting(MergeFilters.class);

        assertThat(sessionSetting.name()).isEqualTo("optimizer_merge_filters");
        assertThat(sessionSetting.description()).isEqualTo("Indicates if the optimizer rule MergeFilters is activated.");
        assertThat(sessionSetting.defaultValue()).isEqualTo("true");

        SearchPath searchPath = SearchPath.createSearchPathFrom("dummySchema");
        var mergefilterSettings = new CoordinatorSessionSettings(
            RolesHelper.userOf("user"),
            RolesHelper.userOf("user"),
            searchPath,
            true,
            Set.of(MergeFilters.class),
            true,
            0,
            false
        );

        assertThat(sessionSetting.getValue(mergefilterSettings)).isEqualTo("false");

        // Disable MergeFilters 'SET SESSION optimizer_merge_filters = false'
        sessionSetting.apply(mergefilterSettings, List.of(Literal.of(false)), eval);
        assertThat(mergefilterSettings.excludedOptimizerRules()).containsExactlyInAnyOrder(MergeFilters.class);

        // Enable MergeFilters 'SET SESSION optimizer_merge_filters = true'
        sessionSetting.apply(mergefilterSettings, List.of(Literal.of(true)), eval);
        assertThat(mergefilterSettings.excludedOptimizerRules()).isEmpty();
    }
}
