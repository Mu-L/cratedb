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


import java.io.IOException;
import java.util.List;

import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.ActionType;
import org.elasticsearch.action.support.ActiveShardCount;
import org.elasticsearch.action.support.master.TransportMasterNodeAction;
import org.elasticsearch.cluster.AckedClusterStateUpdateTask;
import org.elasticsearch.cluster.ClusterState;
import org.elasticsearch.cluster.ack.ClusterStateUpdateResponse;
import org.elasticsearch.cluster.block.ClusterBlockException;
import org.elasticsearch.cluster.block.ClusterBlockLevel;
import org.elasticsearch.cluster.metadata.IndexMetadata;
import org.elasticsearch.cluster.metadata.IndexMetadata.State;
import org.elasticsearch.cluster.metadata.Metadata;
import org.elasticsearch.cluster.metadata.MetadataCreateIndexService;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.Priority;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.inject.Singleton;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.settings.IndexScopedSettings;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.indices.IndicesService;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.TransportService;

import io.crate.common.collections.Lists;
import io.crate.exceptions.RelationAlreadyExists;
import io.crate.execution.ddl.Templates;
import io.crate.execution.ddl.views.TransportCreateView;
import io.crate.metadata.ColumnIdent;
import io.crate.metadata.NodeContext;
import io.crate.metadata.Reference;
import io.crate.metadata.RelationName;
import io.crate.metadata.doc.DocTableInfo;
import io.crate.metadata.doc.DocTableInfoFactory;

/**
 * Action to perform creation of tables on the master but avoid race conditions with creating views.
 *
 * To atomically run the actions on the master, this action wraps around the ES actions and runs them
 * inside this action on the master with checking for views beforehand.
 *
 * See also: {@link TransportCreateView}
 */
@Singleton
public class TransportCreateTableAction extends TransportMasterNodeAction<CreateTableRequest, CreateTableResponse> {

    public static final Action ACTION = new Action();

    public static class Action extends ActionType<CreateTableResponse> {
        private static final String NAME = "internal:crate:sql/tables/admin/create";

        private Action() {
            super(NAME);
        }
    }

    private final MetadataCreateIndexService createIndexService;
    private final IndicesService indicesService;
    private final IndexScopedSettings indexScopedSettings;
    private final DocTableInfoFactory docTableInfoFactory;

    @Inject
    public TransportCreateTableAction(TransportService transportService,
                                      ClusterService clusterService,
                                      NodeContext nodeContext,
                                      ThreadPool threadPool,
                                      IndicesService indicesService,
                                      IndexScopedSettings indexScopedSettings,
                                      MetadataCreateIndexService createIndexService) {
        super(
            ACTION.name(),
            transportService,
            clusterService, threadPool,
            CreateTableRequest::new
        );
        this.createIndexService = createIndexService;
        this.indicesService = indicesService;
        this.indexScopedSettings = indexScopedSettings;
        this.docTableInfoFactory = new DocTableInfoFactory(nodeContext);
    }

    @Override
    protected String executor() {
        return ThreadPool.Names.SAME;
    }

    @Override
    protected CreateTableResponse read(StreamInput in) throws IOException {
        return new CreateTableResponse(in);
    }

    @Override
    protected ClusterBlockException checkBlock(CreateTableRequest request, ClusterState state) {
        var relationName = request.getTableName();
        assert relationName != null : "relationName must not be null";

        var isPartitioned = request.partitionedBy().isEmpty() == false;
        if (isPartitioned) {
            return state.blocks().globalBlockedException(ClusterBlockLevel.METADATA_WRITE);
        } else {
            return state.blocks().indexBlockedException(
                ClusterBlockLevel.METADATA_WRITE,
                relationName.indexNameOrAlias()
            );
        }
    }

    @Override
    protected void masterOperation(CreateTableRequest request,
                                   ClusterState state,
                                   ActionListener<CreateTableResponse> listener) {
        final RelationName relationName = request.getTableName();
        if (state.metadata().contains(relationName)) {
            listener.onFailure(new RelationAlreadyExists(relationName));
            return;
        }

        Settings.Builder settingsBuilder = Settings.builder()
            .put(request.settings())
            .put(
                IndexMetadata.SETTING_INDEX_VERSION_CREATED.getKey(),
                state.nodes().getSmallestNonClientNodeVersion())
            .normalizePrefix(IndexMetadata.INDEX_SETTING_PREFIX);

        Settings normalizedSettings = settingsBuilder.build();

        indexScopedSettings.validate(normalizedSettings, true);

        boolean isPartitioned = !request.partitionedBy().isEmpty();
        ActionListener<ClusterStateUpdateResponse> stateUpdateListener;
        if (isPartitioned) {
            stateUpdateListener = listener.map(resp -> new CreateTableResponse(resp.isAcknowledged()));
        } else {
            stateUpdateListener = createIndexService.withWaitForShards(
                listener,
                relationName.indexNameOrAlias(),
                ActiveShardCount.DEFAULT,
                request.ackTimeout(),
                (stateAck, shardsAck) -> new CreateTableResponse(stateAck && shardsAck)
            );
        }
        var createTableTask = new AckedClusterStateUpdateTask<>(Priority.URGENT, request, stateUpdateListener) {

            @Override
            protected ClusterStateUpdateResponse newResponse(boolean acknowledged) {
                return new ClusterStateUpdateResponse(acknowledged);
            }

            @Override
            public ClusterState execute(ClusterState currentState) throws Exception {
                ClusterState newState;
                if (isPartitioned) {
                    newState = Templates.add(
                        indicesService,
                        createIndexService,
                        currentState,
                        request,
                        normalizedSettings
                    );
                } else {
                    newState = createIndexService.add(currentState, request, normalizedSettings);
                }


                List<String> indexUUIDs = newState.metadata().getIndices(
                    relationName,
                    List.of(),
                    false,
                    imd -> imd.getIndexUUID()
                );

                // To avoid assigning new oids this needs to use references from the already updated metadata
                DocTableInfo docTable = docTableInfoFactory.create(relationName, newState.metadata());
                List<Reference> columns = Lists.map(request.references(), ref -> {
                    ColumnIdent column = ref.column();
                    Reference reference = docTable.getReference(column);
                    return reference != null ? reference : docTable.indexColumn(column);
                });
                Metadata.Builder newMetadata = Metadata.builder(newState.metadata())
                    .setTable(
                        relationName,
                        columns,
                        normalizedSettings,
                        request.routingColumn(),
                        request.tableColumnPolicy(),
                        request.pkConstraintName(),
                        request.checkConstraints(),
                        request.primaryKeys(),
                        request.partitionedBy(),
                        State.OPEN,
                        indexUUIDs
                    );
                return ClusterState.builder(newState).metadata(newMetadata).build();
            }
        };
        clusterService.submitStateUpdateTask("create-table", createTableTask);
    }
}
