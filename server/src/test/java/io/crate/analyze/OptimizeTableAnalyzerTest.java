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

import static io.crate.analyze.OptimizeTableSettings.FLUSH;
import static io.crate.analyze.OptimizeTableSettings.MAX_NUM_SEGMENTS;
import static io.crate.analyze.OptimizeTableSettings.ONLY_EXPUNGE_DELETES;
import static io.crate.analyze.OptimizeTableSettings.UPGRADE_SEGMENTS;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.junit.Before;
import org.junit.Test;

import io.crate.data.RowN;
import io.crate.exceptions.OperationOnInaccessibleRelationException;
import io.crate.exceptions.RelationUnknown;
import io.crate.metadata.PartitionName;
import io.crate.metadata.RelationName;
import io.crate.planner.PlannerContext;
import io.crate.planner.node.ddl.OptimizeTablePlan;
import io.crate.planner.operators.SubQueryResults;
import io.crate.test.integration.CrateDummyClusterServiceUnitTest;
import io.crate.testing.SQLExecutor;

public class OptimizeTableAnalyzerTest extends CrateDummyClusterServiceUnitTest {

    private SQLExecutor e;
    private PlannerContext plannerContext;

    @Before
    public void prepare() throws IOException {
        e = SQLExecutor.of(clusterService)
            .addTable(TableDefinitions.USER_TABLE_DEFINITION)
            .addTable(
                TableDefinitions.TEST_PARTITIONED_TABLE_DEFINITION,
                TableDefinitions.TEST_PARTITIONED_TABLE_PARTITIONS)
            .addBlobTable("create blob table blobs");
        plannerContext = e.getPlannerContext();
    }

    private OptimizeTablePlan.BoundOptimizeTable analyze(String stmt, Object... arguments) {
        AnalyzedOptimizeTable analyzedStatement = e.analyze(stmt);
        return OptimizeTablePlan.bind(
            analyzedStatement,
            plannerContext.transactionContext(),
            plannerContext.nodeContext(),
            new RowN(arguments),
            SubQueryResults.EMPTY,
            plannerContext.clusterState().metadata()
        );
    }

    @Test
    public void testOptimizeSystemTable() throws Exception {
        assertThatThrownBy(() -> analyze("OPTIMIZE TABLE sys.shards"))
            .isExactlyInstanceOf(OperationOnInaccessibleRelationException.class)
            .hasMessage("The relation \"sys.shards\" doesn't support or allow OPTIMIZE operations");
    }

    @Test
    public void testOptimizeTable() throws Exception {
        OptimizeTablePlan.BoundOptimizeTable analysis = analyze("OPTIMIZE TABLE users");
        assertThat(analysis.partitions()).containsExactly(new PartitionName(RelationName.fromIndexName("users"), List.of()));
    }

    @Test
    public void testOptimizeBlobTable() throws Exception {
        OptimizeTablePlan.BoundOptimizeTable analysis = analyze("OPTIMIZE TABLE blob.blobs");
        assertThat(analysis.partitions()).containsExactly(new PartitionName(RelationName.fromIndexName("blob.blobs"), List.of()));
    }

    @Test
    public void testOptimizeTableWithParams() throws Exception {
        OptimizeTablePlan.BoundOptimizeTable analysis = analyze(
            "OPTIMIZE TABLE users WITH (max_num_segments=2)");
        assertThat(analysis.partitions()).containsExactly(new PartitionName(RelationName.fromIndexName("users"), List.of()));
        assertThat(MAX_NUM_SEGMENTS.get(analysis.settings())).isEqualTo(2);
        analysis = analyze("OPTIMIZE TABLE users WITH (only_expunge_deletes=true)");

        assertThat(analysis.partitions()).containsExactly(new PartitionName(RelationName.fromIndexName("users"), List.of()));
        assertThat(ONLY_EXPUNGE_DELETES.get(analysis.settings())).isEqualTo(Boolean.TRUE);

        analysis = analyze("OPTIMIZE TABLE users WITH (flush=false)");
        assertThat(analysis.partitions()).containsExactly(new PartitionName(RelationName.fromIndexName("users"), List.of()));
        assertThat(FLUSH.get(analysis.settings())).isEqualTo(Boolean.FALSE);

        analysis = analyze("OPTIMIZE TABLE users WITH (upgrade_segments=true)");
        assertThat(analysis.partitions()).containsExactly(new PartitionName(RelationName.fromIndexName("users"), List.of()));
        assertThat(UPGRADE_SEGMENTS.get(analysis.settings())).isEqualTo(Boolean.TRUE);
    }

    @Test
    public void testOptimizeTableWithInvalidParamName() throws Exception {
        assertThatThrownBy(() -> analyze("OPTIMIZE TABLE users WITH (invalidParam=123)"))
            .isExactlyInstanceOf(IllegalArgumentException.class)
            .hasMessage("Setting 'invalidparam' is not supported");
    }

    @Test
    public void testOptimizeTableWithUpgradeSegmentsAndOtherParam() throws Exception {
        assertThatThrownBy(() -> analyze("OPTIMIZE TABLE users WITH (flush=false, upgrade_segments=true)"))
            .isExactlyInstanceOf(IllegalArgumentException.class)
            .hasMessage("cannot use other parameters if upgrade_segments is set to true");
    }

    @Test
    public void testOptimizePartition() throws Exception {
        OptimizeTablePlan.BoundOptimizeTable analysis = analyze(
            "OPTIMIZE TABLE parted PARTITION (date=1395874800000)");
        assertThat(analysis.partitions()).containsExactly(new PartitionName(RelationName.fromIndexName("parted"), List.of("1395874800000")));
    }

    @Test
    public void testOptimizePartitionedTableNullPartition() throws Exception {
        OptimizeTablePlan.BoundOptimizeTable analysis = analyze(
            "OPTIMIZE TABLE parted PARTITION (date=null)");
        List<String> nullList = new ArrayList<>();
        nullList.add(null);
        assertThat(analysis.partitions()).containsExactly(new PartitionName(RelationName.fromIndexName("parted"), nullList));
    }

    @Test
    public void testOptimizePartitionWithParams() throws Exception {
        OptimizeTablePlan.BoundOptimizeTable analysis = analyze(
            "OPTIMIZE TABLE parted PARTITION (date=1395874800000) " +
            "WITH (only_expunge_deletes=true)");
        assertThat(analysis.partitions()).containsExactly(new PartitionName(RelationName.fromIndexName("parted"), List.of("1395874800000")));
    }

    @Test
    public void testOptimizeMultipleTables() throws Exception {
        OptimizeTablePlan.BoundOptimizeTable analysis = analyze("OPTIMIZE TABLE parted, users");
        assertThat(analysis.partitions()).hasSize(2);
        assertThat(analysis.partitions())
            .contains(new PartitionName(RelationName.fromIndexName("users"), List.of()),
                      new PartitionName(RelationName.fromIndexName("parted"), List.of()));
    }

    @Test
    public void testOptimizeMultipleTablesUnknown() throws Exception {
        assertThatThrownBy(() -> analyze("OPTIMIZE TABLE parted, foo, bar"))
            .isExactlyInstanceOf(RelationUnknown.class)
            .hasMessage("Relation 'foo' unknown");
    }

    @Test
    public void testOptimizeInvalidPartitioned() throws Exception {
        assertThatThrownBy(() -> analyze("OPTIMIZE TABLE parted PARTITION (invalid_column='hddsGNJHSGFEFZÜ')"))
            .isExactlyInstanceOf(IllegalArgumentException.class)
            .hasMessage("\"invalid_column\" is no known partition column");
    }

    @Test
    public void testOptimizeNonPartitioned() throws Exception {
        assertThatThrownBy(() -> analyze("OPTIMIZE TABLE users PARTITION (foo='n')"))
            .isExactlyInstanceOf(IllegalArgumentException.class)
            .hasMessage("table 'doc.users' is not partitioned");
    }

    @Test
    public void testOptimizeSysPartitioned() throws Exception {
        assertThatThrownBy(() -> analyze("OPTIMIZE TABLE sys.shards PARTITION (id='n')"))
            .isExactlyInstanceOf(OperationOnInaccessibleRelationException.class)
            .hasMessage("The relation \"sys.shards\" doesn't support or allow OPTIMIZE operations");
    }
}
