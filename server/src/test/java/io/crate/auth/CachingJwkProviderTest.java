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

package io.crate.auth;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.util.List;
import java.util.Map;

import org.junit.Test;

import io.netty.handler.codec.http.HttpHeaderNames;

public class CachingJwkProviderTest {

    @Test
    public void test_get_cache_control_max_age_from_request() throws Exception {
        Map<String, List<String>> headers = Map.of(HttpHeaderNames.CACHE_CONTROL.toString(), List.of("max-age=1000"));

        var duration = CachingJwkProvider.cacheControlMaxAgeFromRequest(headers, null);
        assertThat(duration).isEqualTo(Duration.ofSeconds(1000));

        headers = Map.of(HttpHeaderNames.CACHE_CONTROL.toString(), List.of("max-age=1000", "public"));

        duration = CachingJwkProvider.cacheControlMaxAgeFromRequest(headers, null);
        assertThat(duration).isEqualTo(Duration.ofSeconds(1000));

        headers = Map.of(HttpHeaderNames.CACHE_CONTROL.toString(), List.of("foobar", "max-age=1000"));

        duration = CachingJwkProvider.cacheControlMaxAgeFromRequest(headers, null);
        assertThat(duration).isEqualTo(Duration.ofSeconds(1000));

        headers = Map.of(HttpHeaderNames.CACHE_CONTROL.toString(), List.of("foobar", "wrong"));
        duration = CachingJwkProvider.cacheControlMaxAgeFromRequest(headers, null);
        assertThat(duration).isNull();

        headers = Map.of(HttpHeaderNames.CACHE_CONTROL.toString(), List.of("max-age=-1"));
        duration = CachingJwkProvider.cacheControlMaxAgeFromRequest(headers, null);
        assertThat(duration).isNull();

        headers = Map.of(HttpHeaderNames.CACHE_CONTROL.toString(), List.of("max-age=1.1"));
        duration = CachingJwkProvider.cacheControlMaxAgeFromRequest(headers, null);
        assertThat(duration).isNull();

        headers = Map.of(HttpHeaderNames.CACHE_CONTROL.toString(), List.of("max-age=0"));
        duration = CachingJwkProvider.cacheControlMaxAgeFromRequest(headers, null);
        assertThat(duration).isNull();

        headers = Map.of(HttpHeaderNames.CACHE_CONTROL.toString(), List.of("max-age=0"));
        duration = CachingJwkProvider.cacheControlMaxAgeFromRequest(headers, Duration.ofHours(10));
        assertThat(duration).isEqualTo(Duration.ofHours(10));
    }

}
