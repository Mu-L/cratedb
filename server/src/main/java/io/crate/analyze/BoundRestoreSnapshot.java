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

import java.util.List;
import java.util.Set;

import org.elasticsearch.common.settings.Settings;
import org.jetbrains.annotations.Nullable;

import io.crate.metadata.PartitionName;
import io.crate.metadata.RelationName;

public record BoundRestoreSnapshot(String repository,
                                   String snapshot,
                                   Set<RestoreTableInfo> restoreTables,
                                   boolean includeTables,
                                   boolean includeCustomMetadata,
                                   Set<String> customMetadataTypes,
                                   boolean includeGlobalSettings,
                                   List<String> globalSettings,
                                   Settings settings) {

    public static class RestoreTableInfo {

        private final RelationName relationName;
        private final PartitionName partitionName;

        public RestoreTableInfo(RelationName relationName, @Nullable PartitionName partitionName) {
            this.relationName = relationName;
            this.partitionName = partitionName;
        }

        public RelationName tableIdent() {
            return relationName;
        }

        @Nullable
        public PartitionName partitionName() {
            return partitionName;
        }
    }
}
