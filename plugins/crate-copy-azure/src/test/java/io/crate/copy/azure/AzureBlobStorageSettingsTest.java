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

package io.crate.copy.azure;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

import java.net.URI;

import org.elasticsearch.common.settings.Settings;
import org.junit.Test;

public class AzureBlobStorageSettingsTest {

    @Test
    public void test_copy_from_reject_unknown_setting() throws Exception {
        Settings settings = Settings.builder().put("dummy", "dummy").build();

        assertThatThrownBy(() -> new AzureFileInput(null, mock(SharedAsyncExecutor.class), URI.create("azblob:///dir1/dir2/*"), settings))
            .isExactlyInstanceOf(IllegalArgumentException.class)
            .hasMessage("Setting 'dummy' is not supported");
    }

    @Test
    public void test_copy_to_reject_unknown_setting() throws Exception {
        Settings settings = Settings.builder().put("dummy", "dummy").build();

        assertThatThrownBy(() -> new AzureFileOutput(mock(SharedAsyncExecutor.class), settings))
            .isExactlyInstanceOf(IllegalArgumentException.class)
            .hasMessage("Setting 'dummy' is not supported");
    }

    @Test
    public void test_copy_from_requires_auth() throws Exception {
        // Dummy settings to pass required validation
        Settings settings = Settings.builder()
            .put(AzureBlobStorageSettings.CONTAINER_SETTING.getKey(), "dummy")
            .put(AzureBlobStorageSettings.ENDPOINT_SETTING.getKey(), "dummy")
            .build();
        assertThatThrownBy(() -> new AzureFileInput(null, mock(SharedAsyncExecutor.class), URI.create("azblob:///dir1/dir2/*"), settings))
            .isExactlyInstanceOf(IllegalArgumentException.class)
            .hasMessage("Authentication setting must be provided: either sas_token or account and key");
    }

    @Test
    public void test_copy_to_requires_auth() throws Exception {
        // Dummy settings to pass required validation
        Settings settings = Settings.builder()
            .put(AzureBlobStorageSettings.CONTAINER_SETTING.getKey(), "dummy")
            .put(AzureBlobStorageSettings.ENDPOINT_SETTING.getKey(), "dummy")
            .build();
        assertThatThrownBy(() -> new AzureFileOutput(mock(SharedAsyncExecutor.class), settings))
            .isExactlyInstanceOf(IllegalArgumentException.class)
            .hasMessage("Authentication setting must be provided: either sas_token or account and key");
    }

    @Test
    public void test_copy_from_checks_required() throws Exception {
        assertThatThrownBy(() -> new AzureFileInput(null, mock(SharedAsyncExecutor.class), URI.create("azblob:///dir1/dir2/*"), Settings.EMPTY))
            .isExactlyInstanceOf(IllegalArgumentException.class)
            .hasMessage("Setting 'container' must be provided");
    }

    @Test
    public void test_copy_to_checks_required() throws Exception {
        Settings.builder().put(AzureBlobStorageSettings.CONTAINER_SETTING.getKey(), "dummy").build();
        assertThatThrownBy(() -> new AzureFileOutput(mock(SharedAsyncExecutor.class), Settings.EMPTY))
            .isExactlyInstanceOf(IllegalArgumentException.class)
            .hasMessage("Setting 'container' must be provided");
    }

}
