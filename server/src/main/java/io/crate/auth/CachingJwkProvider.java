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

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.Proxy;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLConnection;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.elasticsearch.common.Strings;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.VisibleForTesting;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkProvider;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Expiry;

import io.netty.handler.codec.http.HttpHeaderNames;

/**
 * Custom @{@link JwkProvider} implementation based on
 * <a href="https://github.com/auth0/jwks-rsa-java/blob/master/src/main/java/com/auth0/jwk/UrlJwkProvider.java">UrlJwkProvider.java</a>
 * which caches results of public jwk keys for the duration of the "Cache-Control max-age"
 * Http header value from the response of the jwt authentication endpoint or
 * a provided default value.
 */
public class CachingJwkProvider implements JwkProvider {

    private final URL url;
    private final Proxy proxy;
    private final Map<String, String> headers;
    private final Integer connectTimeout;
    private final Integer readTimeout;
    private final ObjectReader reader;
    private final Cache<String, JwkResult> cache;
    private final Duration cacheExpirationTime;


    public CachingJwkProvider(String domain, Duration cacheExpirationTime) {
        this(urlForDomain(domain), cacheExpirationTime, null, null, null, null);
    }

    public CachingJwkProvider(URL url, Duration cacheExpirationTime, Integer connectTimeout, Integer readTimeout, Proxy proxy, Map<String, String> headers) {
        if (url == null) {
            throw new IllegalArgumentException("A non-null url is required");
        }

        if (connectTimeout != null && connectTimeout < 0) {
            throw new IllegalArgumentException("Invalid connect timeout value '" + connectTimeout + "'. Must be a non-negative integer.");
        }

        if (readTimeout != null && readTimeout < 0) {
            throw new IllegalArgumentException("Invalid read timeout value '" + readTimeout + "'. Must be a non-negative integer.");
        }


        this.url = url;
        this.proxy = proxy;
        this.connectTimeout = connectTimeout;
        this.readTimeout = readTimeout;
        this.reader = new ObjectMapper().readerFor(Map.class);
        this.headers = (headers == null) ?
            Collections.singletonMap("Accept", "application/json") : headers;
        this.cacheExpirationTime = cacheExpirationTime;
        this.cache = Caffeine.newBuilder()
            .maximumSize(5)
            .expireAfter(new Expiry<String, JwkResult>() {

                @Override
                public long expireAfterCreate(String key, JwkResult value, long currentTime) {
                    return value.cacheExpirationTime.toNanos();
                }

                @Override
                public long expireAfterUpdate(String key, JwkResult value, long currentTime, long currentDuration) {
                    return currentDuration;
                }

                @Override
                public long expireAfterRead(String key, JwkResult value, long currentTime, long currentDuration) {
                    return currentDuration;
                }
            }).build();
    }

    static URL urlForDomain(String domain) {
        if (Strings.isNullOrEmpty(domain)) {
            throw new IllegalArgumentException("A domain is required");
        }

        if (!domain.startsWith("http")) {
            domain = "https://" + domain;
        }

        try {
            final URI uri = new URI(domain).normalize();
            return uri.toURL();
        } catch (MalformedURLException | URISyntaxException e) {
            throw new IllegalArgumentException("Invalid jwks uri", e);
        }
    }

    @Override
    public Jwk get(String keyId) {
        return cache.get(keyId, this::getResult).jwk;
    }

    private JwkResult getResult(@NotNull String keyId) {
        final List<Map<String, Object>> keys;
        final Duration ttl;

        try {
            final URLConnection c = (proxy == null) ? this.url.openConnection() : this.url.openConnection(proxy);
            if (connectTimeout != null) {
                c.setConnectTimeout(connectTimeout);
            }
            if (readTimeout != null) {
                c.setReadTimeout(readTimeout);
            }

            for (Map.Entry<String, String> entry : headers.entrySet()) {
                c.setRequestProperty(entry.getKey(), entry.getValue());
            }

            try (InputStream inputStream = c.getInputStream()) {
                Map<String, Object> result = reader.readValue(inputStream);
                ttl = cacheControlMaxAgeFromRequest(c.getHeaderFields(), cacheExpirationTime);
                //noinspection unchecked
                keys = (List<Map<String, Object>>) result.get("keys");
            }
        } catch (IOException e) {
            throw new RuntimeException("Cannot obtain jwks from url " + url, e);
        }

        if (keys == null || keys.isEmpty()) {
            throw new IllegalArgumentException("No keys found in " + url, null);
        }

        List<Jwk> jwks = new ArrayList<>();

        for (Map<String, Object> values : keys) {
            jwks.add(Jwk.fromValues(values));
        }

        if (jwks.size() == 1) {
            return new JwkResult(jwks.get(0), ttl);
        }

        for (Jwk jwk : jwks) {
            if (keyId.equals(jwk.getId())) {
                return new JwkResult(jwk, ttl);
            }
        }
        throw new IllegalArgumentException("No key found in " + url + " with kid " + keyId, null);
    }

    record JwkResult(Jwk jwk, Duration cacheExpirationTime) { }

    @VisibleForTesting
    static Duration cacheControlMaxAgeFromRequest(Map<String, List<String>> headerFields, Duration defaultValue) {
        List<String> cacheControl = headerFields.get(HttpHeaderNames.CACHE_CONTROL.toString());
        if (cacheControl != null) {
            for (String value : cacheControl) {
                if (value.trim().startsWith("max-age=")) {
                    String maxAgeValue = value.substring(value.indexOf("=") + 1);
                    try {
                        int seconds = Integer.parseInt(maxAgeValue);
                        if (seconds > 0) {
                            return Duration.ofSeconds(seconds);
                        }
                    } catch (NumberFormatException ignored) {
                        // Can be ignored, just return null
                    }
                }
            }
        }
        return defaultValue;
    }

}
