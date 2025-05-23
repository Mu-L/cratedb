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

package io.crate.planner.node.ddl;

import static io.crate.analyze.SnapshotSettings.IGNORE_UNAVAILABLE;
import static io.crate.analyze.SnapshotSettings.WAIT_FOR_COMPLETION;

import java.util.HashSet;
import java.util.function.Function;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.action.admin.cluster.snapshots.create.CreateSnapshotRequest;
import org.elasticsearch.action.admin.cluster.snapshots.create.TransportCreateSnapshot;
import org.elasticsearch.cluster.metadata.Metadata;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.snapshots.SnapshotInfo;
import org.elasticsearch.snapshots.SnapshotState;
import org.jetbrains.annotations.VisibleForTesting;

import io.crate.analyze.AnalyzedCreateSnapshot;
import io.crate.analyze.SnapshotSettings;
import io.crate.analyze.SymbolEvaluator;
import io.crate.common.collections.Lists;
import io.crate.data.Row;
import io.crate.data.Row1;
import io.crate.data.RowConsumer;
import io.crate.exceptions.CreateSnapshotException;
import io.crate.exceptions.PartitionUnknownException;
import io.crate.exceptions.ResourceUnknownException;
import io.crate.execution.support.OneRowActionListener;
import io.crate.expression.symbol.Symbol;
import io.crate.metadata.CoordinatorTxnCtx;
import io.crate.metadata.NodeContext;
import io.crate.metadata.PartitionName;
import io.crate.metadata.RelationName;
import io.crate.metadata.Schemas;
import io.crate.metadata.doc.DocTableInfo;
import io.crate.metadata.table.Operation;
import io.crate.metadata.table.SchemaInfo;
import io.crate.metadata.table.TableInfo;
import io.crate.planner.DependencyCarrier;
import io.crate.planner.Plan;
import io.crate.planner.PlannerContext;
import io.crate.planner.operators.SubQueryResults;
import io.crate.sql.tree.GenericProperties;
import io.crate.sql.tree.Table;

public class CreateSnapshotPlan implements Plan {

    private static final Logger LOGGER = LogManager.getLogger(CreateSnapshotPlan.class);


    private final AnalyzedCreateSnapshot createSnapshot;

    public CreateSnapshotPlan(AnalyzedCreateSnapshot createSnapshot) {
        this.createSnapshot = createSnapshot;
    }

    @Override
    public StatementType type() {
        return StatementType.DDL;
    }

    @Override
    public void executeOrFail(DependencyCarrier dependencies,
                              PlannerContext plannerContext,
                              RowConsumer consumer,
                              Row parameters,
                              SubQueryResults subQueryResults) {
        CreateSnapshotRequest request = createRequest(
            createSnapshot,
            plannerContext.transactionContext(),
            dependencies.nodeContext(),
            parameters,
            subQueryResults,
            dependencies.schemas(),
            plannerContext.clusterState().metadata());

        dependencies.client().execute(TransportCreateSnapshot.ACTION, request)
            .whenComplete(
                new OneRowActionListener<>(
                    consumer,
                    response -> {
                        SnapshotInfo snapshotInfo = response.getSnapshotInfo();
                        if (snapshotInfo != null &&  // if wait_for_completion is false, the snapshotInfo is null
                            snapshotInfo.state() == SnapshotState.FAILED) {
                            // fail request if snapshot creation failed
                            String reason = response.getSnapshotInfo().reason()
                                .replaceAll("Index", "Table")
                                .replaceAll("Indices", "Tables");
                            var createSnapshotException = new CreateSnapshotException(
                                createSnapshot.repositoryName(),
                                createSnapshot.snapshotName(),
                                reason
                            );
                            consumer.accept(null, createSnapshotException);
                            return new Row1(-1L);
                        } else {
                            return new Row1(1L);
                        }
                    }));
    }

    @VisibleForTesting
    public static CreateSnapshotRequest createRequest(AnalyzedCreateSnapshot createSnapshot,
                                                      CoordinatorTxnCtx txnCtx,
                                                      NodeContext nodeCtx,
                                                      Row parameters,
                                                      SubQueryResults subQueryResults,
                                                      Schemas schemas,
                                                      Metadata metadata) {
        Function<? super Symbol, Object> eval = x -> SymbolEvaluator.evaluate(
            txnCtx,
            nodeCtx,
            x,
            parameters,
            subQueryResults
        );

        GenericProperties<Object> properties = createSnapshot.properties()
            .ensureContainsOnly(SnapshotSettings.SETTINGS.keySet())
            .map(eval);
        Settings settings = Settings.builder().put(properties).build();

        boolean ignoreUnavailable = IGNORE_UNAVAILABLE.get(settings);

        final HashSet<RelationName> snapshotTables;
        final HashSet<PartitionName> snapshotPartitions = new HashSet<>();
        if (createSnapshot.tables().isEmpty()) {
            for (SchemaInfo schemaInfo : schemas) {
                for (TableInfo tableInfo : schemaInfo.getTables()) {
                    // only check for user generated tables
                    if (tableInfo instanceof DocTableInfo) {
                        Operation.blockedRaiseException(tableInfo, Operation.READ);
                    }
                }
            }
            snapshotTables = new HashSet<>();
        } else {
            snapshotTables = HashSet.newHashSet(createSnapshot.tables().size());
            for (Table<Symbol> table : createSnapshot.tables()) {
                DocTableInfo docTableInfo;
                try {
                    docTableInfo = schemas.findRelation(
                        table.getName(),
                        Operation.CREATE_SNAPSHOT,
                        txnCtx.sessionSettings().sessionUser(),
                        txnCtx.sessionSettings().searchPath()
                    );
                } catch (Exception e) {
                    if (ignoreUnavailable && e instanceof ResourceUnknownException) {
                        LOGGER.info(
                            "Ignore unknown relation '{}' for the '{}' snapshot'",
                            table.getName(), createSnapshot.snapshotName());
                        continue;
                    } else {
                        throw e;
                    }
                }

                // Only add tables as snapshot tables, partitions are added separately, they also include their table
                if (table.partitionProperties().isEmpty()) {
                    snapshotTables.add(docTableInfo.ident());
                } else {
                    try {
                        PartitionName partitionName = PartitionName.ofAssignments(docTableInfo, Lists.map(table.partitionProperties(), x -> x.map(eval)), metadata);
                        snapshotPartitions.add(partitionName);
                    } catch (PartitionUnknownException ex) {
                        if (ignoreUnavailable) {
                            LOGGER.info(
                                "ignoring unknown partition of table '{}' with ident '{}'",
                                ex.partitionName().relationName(),
                                ex.partitionName().ident());
                        } else {
                            throw ex;
                        }
                    }
                }
            }
        }

        return new CreateSnapshotRequest(createSnapshot.repositoryName(), createSnapshot.snapshotName())
            .includeGlobalState(createSnapshot.tables().isEmpty())
            .waitForCompletion(WAIT_FOR_COMPLETION.get(settings))
            .relationNames(snapshotTables.stream().toList())
            .partitionNames(snapshotPartitions.stream().toList())
            .settings(settings);
    }
}
