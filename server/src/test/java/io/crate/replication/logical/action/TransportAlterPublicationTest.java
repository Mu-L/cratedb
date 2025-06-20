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

package io.crate.replication.logical.action;

import static io.crate.testing.TestingHelpers.createNodeContext;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import java.util.Set;

import org.elasticsearch.Version;
import org.elasticsearch.cluster.metadata.IndexMetadata;
import org.elasticsearch.cluster.metadata.Metadata;
import org.elasticsearch.cluster.metadata.MetadataUpgradeService;
import org.elasticsearch.common.settings.IndexScopedSettings;
import org.elasticsearch.common.settings.Settings;
import org.junit.Before;
import org.junit.Test;

import io.crate.exceptions.RelationUnknown;
import io.crate.metadata.NodeContext;
import io.crate.metadata.RelationName;
import io.crate.replication.logical.metadata.Publication;
import io.crate.sql.tree.AlterPublication;
import io.crate.test.integration.CrateDummyClusterServiceUnitTest;

public class TransportAlterPublicationTest extends CrateDummyClusterServiceUnitTest {

    private final NodeContext nodeCtx = createNodeContext();
    private MetadataUpgradeService metadataUpgradeService;

    @Before
    public void setUpUpgradeService() throws Exception {
        metadataUpgradeService = new MetadataUpgradeService(
            nodeCtx,
            new IndexScopedSettings(Settings.EMPTY, Set.of()),
            null
        );
    }

    @Test
    public void test_unknown_table_raises_exception() {
        var pub = new Publication("owner", false, List.of());
        var metadata = Metadata.builder().build();
        var request = new TransportAlterPublication.Request(
            "pub1",
            AlterPublication.Operation.SET,
            List.of(RelationName.fromIndexName("t1"))
        );

        assertThatThrownBy(() -> TransportAlterPublication.updatePublication(request, metadata, pub))
            .isExactlyInstanceOf(RelationUnknown.class);
    }

    @Test
    public void test_set_tables_on_existing_publication() {
        var oldPublication = new Publication("owner", false, List.of(RelationName.fromIndexName("t1")));
        var metadata = Metadata.builder()
            .put(IndexMetadata.builder("t2")
                .settings(settings(Version.CURRENT))
                .numberOfShards(1)
                .numberOfReplicas(0)
                .build(),
                true
            )
            .build();
        var request = new TransportAlterPublication.Request(
            "pub1",
            AlterPublication.Operation.SET,
            List.of(RelationName.fromIndexName("t2"))
        );

        metadata = metadataUpgradeService.upgradeMetadata(metadata);
        var newPublication = TransportAlterPublication.updatePublication(request, metadata, oldPublication);
        assertThat(newPublication).isNotEqualTo(oldPublication);
        assertThat(newPublication.tables()).containsExactly(RelationName.fromIndexName("t2"));
    }

    @Test
    public void test_add_table_on_existing_publication() {
        var oldPublication = new Publication("owner", false, List.of(RelationName.fromIndexName("t1")));
        var metadata = Metadata.builder()
            .put(IndexMetadata.builder("t2")
                .settings(settings(Version.CURRENT))
                .numberOfShards(1)
                .numberOfReplicas(0)
                .build(),
                true
            )
            .build();
        var request = new TransportAlterPublication.Request(
            "pub1",
            AlterPublication.Operation.ADD,
            List.of(RelationName.fromIndexName("t2"))
        );

        metadata = metadataUpgradeService.upgradeMetadata(metadata);
        var newPublication = TransportAlterPublication.updatePublication(request, metadata, oldPublication);
        assertThat(newPublication).isNotEqualTo(oldPublication);
        assertThat(newPublication.tables()).containsExactlyInAnyOrder(
            RelationName.fromIndexName("t1"), RelationName.fromIndexName("t2"));
    }

    @Test
    public void test_drop_table_from_existing_publication() {
        var oldPublication = new Publication(
            "owner",
            false,
            List.of(RelationName.fromIndexName("t1"), RelationName.fromIndexName("t2"))
        );
        var metadata = Metadata.builder()
            .put(IndexMetadata.builder("t2")
                .settings(settings(Version.CURRENT))
                .numberOfShards(1)
                .numberOfReplicas(0)
                .build(),
                true
            )
            .build();

        var request = new TransportAlterPublication.Request(
            "pub1",
            AlterPublication.Operation.DROP,
            List.of(RelationName.fromIndexName("t2"))
        );
        metadata = metadataUpgradeService.upgradeMetadata(metadata);

        var newPublication = TransportAlterPublication.updatePublication(request, metadata, oldPublication);
        assertThat(newPublication).isNotEqualTo(oldPublication);
        assertThat(newPublication.tables()).containsExactly(RelationName.fromIndexName("t1"));
    }
}
