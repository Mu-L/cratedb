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

package io.crate.integrationtests;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;

import org.apache.lucene.tests.util.TestUtil;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.env.Environment;
import org.elasticsearch.test.IntegTestCase;
import org.junit.Test;

@IntegTestCase.ClusterScope(numDataNodes = 0, numClientNodes = 0)
public class TablesNeedUpgradeSysCheckTest extends IntegTestCase {

    private void startUpNodeWithDataDir(String dataPath) throws Exception {
        Path indexDir = createTempDir();
        try (InputStream stream = Files.newInputStream(getDataPath(dataPath))) {
            TestUtil.unzip(stream, indexDir);
        }
        Settings.Builder builder = Settings.builder().put(Environment.PATH_DATA_SETTING.getKey(), indexDir.toAbsolutePath());
        cluster().startNode(builder.build());
        ensureGreen();
    }

    @Test
    public void test_4x_indices_not_supported() throws Exception {
        assertThatThrownBy(() -> startUpNodeWithDataDir("/indices/data_home/cratedata-4.3.0.zip"))
            .hasMessageContaining("was created with version [4.3.0] but the minimum compatible version is [5.0.0]");
    }
}
