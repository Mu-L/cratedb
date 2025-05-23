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

package io.crate.execution.ddl.tables;

import static io.crate.testing.Asserts.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.elasticsearch.cluster.metadata.Metadata.COLUMN_OID_UNASSIGNED;

import java.util.List;
import java.util.Map;

import org.elasticsearch.Version;
import org.elasticsearch.cluster.ClusterState;
import org.elasticsearch.cluster.metadata.IndexMetadata;
import org.elasticsearch.common.settings.Settings;
import org.junit.Test;

import com.carrotsearch.hppc.IntArrayList;

import io.crate.metadata.GeoReference;
import io.crate.metadata.IndexType;
import io.crate.metadata.Reference;
import io.crate.metadata.ReferenceIdent;
import io.crate.metadata.RelationName;
import io.crate.metadata.RowGranularity;
import io.crate.metadata.SimpleReference;
import io.crate.metadata.doc.DocTableInfo;
import io.crate.metadata.doc.DocTableInfoFactory;
import io.crate.test.integration.CrateDummyClusterServiceUnitTest;
import io.crate.testing.SQLExecutor;
import io.crate.types.ArrayType;
import io.crate.types.DataTypes;

public class AddColumnTaskTest extends CrateDummyClusterServiceUnitTest {

    private static AlterTableTask<AddColumnRequest> buildAddColumnTask(SQLExecutor e, RelationName tblName) {
        return new AlterTableTask<>(
            e.nodeCtx, tblName, e.fulltextAnalyzerResolver(), TransportAddColumn.ADD_COLUMN_OPERATOR);
    }

    @Test
    public void test_can_add_child_column() throws Exception {
        var e = SQLExecutor.of(clusterService)
            .addTable("create table tbl (x int, o object)");
        DocTableInfo tbl = e.resolveTableInfo("tbl");
        var addColumnTask = buildAddColumnTask(e, tbl.ident());
        ReferenceIdent refIdent = new ReferenceIdent(tbl.ident(), "o", List.of("x"));
        SimpleReference newColumn = new SimpleReference(
            refIdent,
            RowGranularity.DOC,
            DataTypes.INTEGER,
            IndexType.PLAIN,
            true,
            true,
            3,
            COLUMN_OID_UNASSIGNED,
            false,
            null
        );
        List<Reference> columns = List.of(newColumn);
        var request = new AddColumnRequest(
            tbl.ident(),
            columns,
            Map.of(),
            new IntArrayList()
        );
        ClusterState newState = addColumnTask.execute(clusterService.state(), request);
        DocTableInfo newTable = new DocTableInfoFactory(e.nodeCtx).create(tbl.ident(), newState.metadata());

        Reference addedColumn = newTable.getReference(newColumn.column());
        // Need to create a clone of request column to imitate the expected OID.
        Reference newColumnWithOid = new SimpleReference(
            newColumn.ident(),
            newColumn.granularity(),
            newColumn.valueType(),
            newColumn.indexType(),
            newColumn.isNullable(),
            newColumn.hasDocValues(),
            newColumn.position(),
            3,
            false,
            newColumn.defaultExpression()
        );
        assertThat(addedColumn).isEqualTo(newColumnWithOid);
    }



    @Test
    public void test_can_add_geo_shape_array_column() throws Exception {
        var e = SQLExecutor.of(clusterService)
            .addTable("create table tbl (x int)");
        DocTableInfo tbl = e.resolveTableInfo("tbl");
        var addColumnTask = buildAddColumnTask(e, tbl.ident());
        ReferenceIdent shapesIdent = new ReferenceIdent(tbl.ident(), "shapes");

        Reference geoShapeArrayRef = new GeoReference(
            shapesIdent,
            new ArrayType<>(DataTypes.GEO_SHAPE),
            IndexType.PLAIN,
            true,
            2,
            COLUMN_OID_UNASSIGNED,
            false,
            null,
            null,
            null,
            null,
            null
        );

        ReferenceIdent pointsIdent = new ReferenceIdent(tbl.ident(), "points");
        Reference geoPointArrayRef = new GeoReference(
            pointsIdent,
            new ArrayType<>(DataTypes.GEO_POINT),
            IndexType.PLAIN,
            true,
            3,
            COLUMN_OID_UNASSIGNED,
            false,
            null,
            null,
            null,
            null,
            null
        );
        List<Reference> columns = List.of(geoShapeArrayRef, geoPointArrayRef);
        var request = new AddColumnRequest(
            tbl.ident(),
            columns,
            Map.of(),
            new IntArrayList()
        );
        ClusterState newState = addColumnTask.execute(clusterService.state(), request);
        DocTableInfo newTable = new DocTableInfoFactory(e.nodeCtx).create(tbl.ident(), newState.metadata());

        Reference addedShapesColumn = newTable.getReference(shapesIdent.columnIdent());
        assertThat(addedShapesColumn.valueType()).isEqualTo(new ArrayType<>(DataTypes.GEO_SHAPE));

        Reference addedPointsColumn = newTable.getReference(pointsIdent.columnIdent());
        assertThat(addedPointsColumn.valueType()).isEqualTo(new ArrayType<>(DataTypes.GEO_POINT));
    }

    @Test
    public void test_is_no_op_if_columns_exist() throws Exception {
        /*
         * The cluster state update logic later asserts that the mapping source must have changed if
         * the version increases. Without no-op check this assertion would trip
         * if there are concurrent alter table (or more likely: Dynamic mapping updates due to concurrent inserts)
         */
        var e = SQLExecutor.of(clusterService)
            .addTable("create table tbl (x int)");
        DocTableInfo tbl = e.resolveTableInfo("tbl");
        ClusterState state = clusterService.state();
        var addColumnTask = buildAddColumnTask(e, tbl.ident());
        ReferenceIdent refIdent = new ReferenceIdent(tbl.ident(), "x");
        SimpleReference newColumn = new SimpleReference(
            refIdent,
            RowGranularity.DOC,
            DataTypes.INTEGER,
            3,
            null
        );
        List<Reference> columns = List.of(newColumn);
        var request = new AddColumnRequest(
            tbl.ident(),
            columns,
            Map.of(),
            new IntArrayList()
        );
        ClusterState newState = addColumnTask.execute(state, request);
        assertThat(newState).isSameAs(state);
    }

    @Test
    public void test_raises_error_if_column_already_exists_with_different_type() throws Exception {
        var e = SQLExecutor.of(clusterService)
            .addTable("create table tbl (x int)");
        DocTableInfo tbl = e.resolveTableInfo("tbl");
        ClusterState state = clusterService.state();
        var addColumnTask = buildAddColumnTask(e, tbl.ident());
        ReferenceIdent refIdent1 = new ReferenceIdent(tbl.ident(), "y");
        ReferenceIdent refIdent2 = new ReferenceIdent(tbl.ident(), "x");
        SimpleReference newColumn1 = new SimpleReference(
            refIdent1,
            RowGranularity.DOC,
            DataTypes.STRING,
            3,
            null
        );
        SimpleReference newColumn2 = new SimpleReference(
            refIdent2,
            RowGranularity.DOC,
            DataTypes.STRING,
            4,
            null
        );
        List<Reference> columns = List.of(newColumn1, newColumn2);
        var request = new AddColumnRequest(
            tbl.ident(),
            columns,
            Map.of(),
            new IntArrayList()
        );
        assertThatThrownBy(() -> addColumnTask.execute(state, request))
            .isExactlyInstanceOf(IllegalArgumentException.class)
            .hasMessage("Column `x` already exists with type `integer`. Cannot add same column with type `text`");
    }

    @Test
    public void test_supports_nested_arrays() throws Exception {
        var e = SQLExecutor.of(clusterService)
            .addTable("create table tbl (x int)");
        DocTableInfo tbl = e.resolveTableInfo("tbl");
        ClusterState state = clusterService.state();
        var addColumnTask = buildAddColumnTask(e, tbl.ident());
        SimpleReference newColumn1 = new SimpleReference(
            new ReferenceIdent(tbl.ident(), "y"),
            RowGranularity.DOC,
            new ArrayType<>(new ArrayType<>(DataTypes.LONG)),
            2,
            null
        );
        List<Reference> columns = List.of(newColumn1);
        var request = new AddColumnRequest(
            tbl.ident(),
            columns,
            Map.of(),
            new IntArrayList()
        );
        ClusterState newState = addColumnTask.execute(state, request);
        DocTableInfo newTable = new DocTableInfoFactory(e.nodeCtx).create(tbl.ident(), newState.metadata());
        Reference addedColumn = newTable.getReference(newColumn1.column());
        assertThat(addedColumn).hasType(new ArrayType<>(new ArrayType<>(DataTypes.LONG)));
    }

    @Test
    public void test_table_version_less_than_5_5_oid_is_not_assigned() throws Exception {
        var e = SQLExecutor.of(clusterService)
            .addTable(
                "create table tbl (x int)",
                Settings.builder().put(IndexMetadata.SETTING_INDEX_VERSION_CREATED.getKey(), Version.V_5_4_0).build()
            );

        DocTableInfo tbl = e.resolveTableInfo("tbl");
        var addColumnTask = buildAddColumnTask(e, tbl.ident());

        SimpleReference colToAdd = new SimpleReference(
            new ReferenceIdent(tbl.ident(), "y"),
            RowGranularity.DOC,
            DataTypes.STRING,
            2,
            null
        );

        List<Reference> columns = List.of(colToAdd);
        var request = new AddColumnRequest(
            tbl.ident(),
            columns,
            Map.of(),
            new IntArrayList()
        );
        ClusterState newState = addColumnTask.execute(clusterService.state(), request);
        DocTableInfo newTable = new DocTableInfoFactory(e.nodeCtx).create(tbl.ident(), newState.metadata());

        Reference addedColumn = newTable.getReference(colToAdd.column());
        assertThat(addedColumn).hasOid(COLUMN_OID_UNASSIGNED);
    }

    @Test
    public void test_cannot_add_column_that_clashes_with_index() throws Exception {
        var e = SQLExecutor.of(clusterService)
            .addTable("create table tbl (x text, index i using fulltext (x))");

        DocTableInfo tbl = e.resolveTableInfo("tbl");
        var addColumnTask = buildAddColumnTask(e, tbl.ident());
        SimpleReference colToAdd = new SimpleReference(
            new ReferenceIdent(tbl.ident(), "i"),
            RowGranularity.DOC,
            DataTypes.STRING,
            2,
            null
        );
        List<Reference> columns = List.of(colToAdd);
        var request = new AddColumnRequest(
            tbl.ident(),
            columns,
            Map.of(),
            new IntArrayList()
        );
        assertThatThrownBy(() -> addColumnTask.execute(clusterService.state(), request))
            .isExactlyInstanceOf(UnsupportedOperationException.class)
            .hasMessage("Index column `i` already exists");
    }
}
