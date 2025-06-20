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

package io.crate.metadata.cluster;

import java.util.Collection;
import java.util.List;

import org.elasticsearch.cluster.ClusterState;
import org.elasticsearch.cluster.metadata.IndexMetadata;
import org.elasticsearch.cluster.metadata.Metadata;
import org.elasticsearch.cluster.metadata.MetadataDeleteIndexService;
import org.elasticsearch.index.Index;

import io.crate.exceptions.RelationUnknown;
import io.crate.execution.ddl.tables.DropTableRequest;
import io.crate.metadata.RelationName;

public class DropTableClusterStateTaskExecutor extends DDLClusterStateTaskExecutor<DropTableRequest> {

    private final MetadataDeleteIndexService deleteIndexService;
    private final DDLClusterStateService ddlClusterStateService;

    public DropTableClusterStateTaskExecutor(MetadataDeleteIndexService deleteIndexService,
                                             DDLClusterStateService ddlClusterStateService) {
        this.deleteIndexService = deleteIndexService;
        this.ddlClusterStateService = ddlClusterStateService;
    }

    @Override
    protected ClusterState execute(ClusterState currentState, DropTableRequest request) throws Exception {
        RelationName relationName = request.tableIdent();
        Metadata currentMetadata = currentState.metadata();

        if (!currentMetadata.contains(relationName)) {
            throw new RelationUnknown(relationName);
        }
        Collection<Index> indices = currentMetadata.getIndices(
            relationName,
            List.of(),
            false,
            IndexMetadata::getIndex
        );
        Metadata.Builder newMetadata = Metadata.builder(currentMetadata)
            .dropRelation(relationName);

        currentState = ClusterState.builder(currentState)
            .metadata(newMetadata)
            .build();

        currentState = deleteIndexService.deleteIndices(currentState, indices);

        // call possible modifiers
        currentState = ddlClusterStateService.onDropTable(currentState, relationName);

        return currentState;
    }
}
