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

package io.crate.execution.engine.indexing;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Executor;
import java.util.concurrent.ScheduledExecutorService;
import java.util.function.Predicate;
import java.util.function.Supplier;

import org.jetbrains.annotations.Nullable;

import org.elasticsearch.client.ElasticsearchClient;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.breaker.CircuitBreaker;
import org.elasticsearch.common.settings.Settings;

import io.crate.data.BatchIterator;
import io.crate.data.CollectingBatchIterator;
import io.crate.data.Input;
import io.crate.data.Projector;
import io.crate.data.Row;
import io.crate.data.breaker.RamAccounting;
import io.crate.execution.dml.upsert.ShardUpsertRequest;
import io.crate.execution.dml.upsert.ShardUpsertRequest.DuplicateKeyAction;
import io.crate.execution.engine.collect.CollectExpression;
import io.crate.execution.engine.collect.RowShardResolver;
import io.crate.execution.jobs.NodeLimits;
import io.crate.expression.symbol.Assignments;
import io.crate.expression.symbol.Symbol;
import io.crate.metadata.ColumnIdent;
import io.crate.metadata.NodeContext;
import io.crate.metadata.Reference;
import io.crate.metadata.TransactionContext;

public class ColumnIndexWriterProjector implements Projector {
    private final ShardingUpsertExecutor shardingUpsertExecutor;

    public ColumnIndexWriterProjector(ClusterService clusterService,
                                      NodeLimits nodeJobsCounter,
                                      CircuitBreaker queryCircuitBreaker,
                                      RamAccounting ramAccounting,
                                      ScheduledExecutorService scheduler,
                                      Executor executor,
                                      TransactionContext txnCtx,
                                      NodeContext nodeCtx,
                                      Settings settings,
                                      int targetTableNumShards,
                                      int targetTableNumReplicas,
                                      Supplier<String> indexNameResolver,
                                      ElasticsearchClient elasticsearchClient,
                                      List<ColumnIdent> primaryKeyIdents,
                                      List<? extends Symbol> primaryKeySymbols,
                                      @Nullable Symbol routingSymbol,
                                      ColumnIdent clusteredByColumn,
                                      Supplier<Reference[]> columnReferencesSupplier,
                                      Supplier<List<Input<?>>> insertInputsSupplier,
                                      Supplier<List<? extends CollectExpression<Row, ?>>> collectExpressionsSupplier,
                                      boolean ignoreDuplicateKeys,
                                      boolean overwriteDuplicateKeys,
                                      boolean failFast,
                                      boolean validation,
                                      @Nullable Map<Reference, Symbol> onConflictAssignmentsByRef,
                                      int bulkActions,
                                      boolean autoCreateIndices,
                                      List<Symbol> returnValues,
                                      UUID jobId,
                                      UpsertResultContext upsertResultContext) {
        RowShardResolver rowShardResolver = new RowShardResolver(
            txnCtx, nodeCtx, primaryKeyIdents, primaryKeySymbols, clusteredByColumn, routingSymbol);
        String[] onConflictColumns;
        Symbol[] onConflictAssignments;
        if (onConflictAssignmentsByRef == null) {
            onConflictColumns = null;
            onConflictAssignments = null;
        } else {
            Assignments convert = Assignments.convert(onConflictAssignmentsByRef, nodeCtx);
            onConflictColumns = convert.targetNames();
            onConflictAssignments = convert.sources();
        }
        DuplicateKeyAction duplicateKeyAction = DuplicateKeyAction.UPDATE_OR_FAIL; // Common fallback for insert from sub-query and COPY FROM.
        if (ignoreDuplicateKeys) {
            assert overwriteDuplicateKeys == false : "Only one of ignore/overwrite duplicate keys can be true";
            duplicateKeyAction = DuplicateKeyAction.IGNORE;
        } else if (overwriteDuplicateKeys) {
            assert ignoreDuplicateKeys == false : "Only one of ignore/overwrite duplicate keys can be true";
            duplicateKeyAction = DuplicateKeyAction.OVERWRITE;
        }
        ShardUpsertRequest.Builder builder = new ShardUpsertRequest.Builder(
            txnCtx.sessionSettings(),
            ShardingUpsertExecutor.BULK_REQUEST_TIMEOUT_SETTING.get(settings),
            duplicateKeyAction,
            true, // continueOnErrors
            onConflictColumns,
            columnReferencesSupplier,
            returnValues.isEmpty() ? null : returnValues.toArray(new Symbol[0]),
            jobId,
            validation); // TODO: actually use it in TransportShardUpsertAction/Indexer.

        ItemFactory<ShardUpsertRequest.Item> itemFactory = (id, pkValues, autoGeneratedTimestamp) -> ShardUpsertRequest.Item.forInsert(
            id,
            pkValues,
            autoGeneratedTimestamp,
            insertInputsSupplier,
            onConflictAssignments
        );

        Predicate<UpsertResults> earlyTerminationCondition = results -> failFast && results.containsErrors();

        shardingUpsertExecutor = new ShardingUpsertExecutor(
            clusterService,
            nodeJobsCounter,
            queryCircuitBreaker,
            ramAccounting,
            scheduler,
            executor,
            bulkActions,
            jobId,
            rowShardResolver,
            itemFactory,
            builder::newRequest,
            collectExpressionsSupplier,
            columnReferencesSupplier,
            indexNameResolver,
            autoCreateIndices,
            elasticsearchClient,
            targetTableNumShards,
            targetTableNumReplicas,
            upsertResultContext,
            earlyTerminationCondition,
            UpsertResults::resultsToFailure
        );
    }

    @Override
    public BatchIterator<Row> apply(BatchIterator<Row> batchIterator) {
        return CollectingBatchIterator.newInstance(batchIterator, shardingUpsertExecutor, batchIterator.hasLazyResultSet());
    }

    @Override
    public boolean providesIndependentScroll() {
        return false;
    }
}
