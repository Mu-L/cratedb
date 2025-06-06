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

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.function.BinaryOperator;
import java.util.function.Function;
import java.util.function.Supplier;

import org.elasticsearch.cluster.node.DiscoveryNode;

import com.carrotsearch.hppc.IntArrayList;

import io.crate.auth.AccessControl;
import io.crate.data.CollectionBucket;
import io.crate.data.Row;
import io.crate.data.Row1;
import io.crate.exceptions.SQLExceptions;
import io.crate.execution.dml.ShardResponse;
import io.crate.execution.dml.ShardResponse.Failure;

final class UpsertResultCollectors {

    static UpsertResultCollector newResultRowCollector() {
        return new ResultRowCollector();
    }

    static UpsertResultCollector newRowCountCollector() {
        return new RowCountCollector();
    }

    static UpsertResultCollector newSummaryCollector(DiscoveryNode localNode, AccessControl accessControl) {
        return new SummaryCollector(Map.of(
            "id", localNode.getId(),
            "name", localNode.getName()
        ), accessControl);
    }

    private static class ResultRowCollector implements UpsertResultCollector {

        @Override
        public Supplier<UpsertResults> supplier() {
            return UpsertResults::new;
        }

        @Override
        public Accumulator accumulator() {
            return this::processShardResponse;
        }

        @Override
        public BinaryOperator<UpsertResults> combiner() {
            return (i, o) -> {
                synchronized (i) {
                    i.addResultRows(o.getResultRowsForNoUri());
                }
                return i;
            };
        }

        @Override
        public Function<UpsertResults, Iterable<Row>> finisher() {
            return r -> new CollectionBucket(r.getResultRowsForNoUri());
        }

        void processShardResponse(UpsertResults upsertResults,
                                  ShardResponse shardResponse,
                                  List<RowSourceInfo> rowSourceInfosIgnored) {
            List<Object[]> resultRows = shardResponse.getResultRows();
            if (resultRows != null) {
                synchronized (upsertResults) {
                    upsertResults.addResultRows(resultRows);
                }
            }
        }
    }

    private static class RowCountCollector implements UpsertResultCollector {

        @Override
        public Supplier<UpsertResults> supplier() {
            return UpsertResults::new;
        }

        @Override
        public Accumulator accumulator() {
            return this::processShardResponse;
        }

        @Override
        public BinaryOperator<UpsertResults> combiner() {
            return (i, o) -> {
                synchronized (i) {
                    i.merge(o);
                }
                return i;
            };
        }

        @Override
        public Function<UpsertResults, Iterable<Row>> finisher() {
            return r -> Collections.singletonList(new Row1(r.getSuccessRowCountForNoUri()));
        }

        void processShardResponse(UpsertResults upsertResults,
                                  ShardResponse shardResponse,
                                  List<RowSourceInfo> rowSourceInfosIgnored) {
            Failure failure = shardResponse.failures().stream()
                .filter(x -> x != null && x.error() != null)
                .findAny()
                .orElse(null);
            synchronized (upsertResults) {
                upsertResults.addResult(shardResponse.successRowCount(), failure);
            }
        }
    }

    private static class SummaryCollector implements UpsertResultCollector {

        private final Map<String, String> nodeInfo;
        private final AccessControl accessControl;

        SummaryCollector(Map<String, String> nodeInfo, AccessControl accessControl) {
            this.nodeInfo = nodeInfo;
            this.accessControl = accessControl;
        }

        @Override
        public Supplier<UpsertResults> supplier() {
            return () -> new UpsertResults(nodeInfo);
        }

        @Override
        public Accumulator accumulator() {
            return this::processShardResponse;
        }

        @Override
        public BinaryOperator<UpsertResults> combiner() {
            return (i, o) -> {
                synchronized (i) {
                    i.merge(o);
                }
                return i;
            };
        }

        @Override
        public Function<UpsertResults, Iterable<Row>> finisher() {
            return UpsertResults::rowsIterable;
        }

        void processShardResponse(UpsertResults upsertResults,
                                  ShardResponse shardResponse,
                                  List<RowSourceInfo> rowSourceInfos) {
            List<ShardResponse.Failure> failures = shardResponse.failures();
            IntArrayList locations = shardResponse.itemIndices();
            synchronized (upsertResults) {
                for (int i = 0; i < failures.size(); i++) {
                    ShardResponse.Failure failure = failures.get(i);
                    int location = locations.get(i);
                    RowSourceInfo rowSourceInfo = rowSourceInfos.get(location);
                    String msg = null;
                    if (failure != null) {
                        Throwable error = failure.error();
                        if (error == null) {
                            msg = "unknown failure";
                        } else {
                            var throwable = SQLExceptions.prepareForClientTransmission(
                                accessControl,
                                failure.error()
                            );
                            msg = throwable.getMessage();
                        }
                    }
                    upsertResults.addResult(rowSourceInfo.sourceUri, msg, rowSourceInfo.lineNumber);
                }
            }
        }
    }

    private UpsertResultCollectors() {
    }
}
