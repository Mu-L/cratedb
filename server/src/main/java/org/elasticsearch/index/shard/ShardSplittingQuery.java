/*
 * Licensed to Elasticsearch under one or more contributor
 * license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright
 * ownership. Elasticsearch licenses this file to you under
 * the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.elasticsearch.index.shard;

import org.apache.lucene.index.FieldInfo;
import org.apache.lucene.index.LeafReader;
import org.apache.lucene.index.LeafReaderContext;
import org.apache.lucene.index.PostingsEnum;
import org.apache.lucene.index.StoredFieldVisitor;
import org.apache.lucene.index.Terms;
import org.apache.lucene.index.TermsEnum;
import org.apache.lucene.search.ConstantScoreScorer;
import org.apache.lucene.search.ConstantScoreWeight;
import org.apache.lucene.search.DocIdSetIterator;
import org.apache.lucene.search.IndexSearcher;
import org.apache.lucene.search.Query;
import org.apache.lucene.search.ScoreMode;
import org.apache.lucene.search.Scorer;
import org.apache.lucene.search.TwoPhaseIterator;
import org.apache.lucene.search.Weight;
import org.apache.lucene.util.BitSetIterator;
import org.apache.lucene.util.BytesRef;
import org.apache.lucene.util.FixedBitSet;
import org.elasticsearch.cluster.metadata.IndexMetadata;
import org.elasticsearch.cluster.routing.OperationRouting;
import org.elasticsearch.index.mapper.IdFieldMapper;
import org.elasticsearch.index.mapper.Uid;

import java.io.IOException;
import java.util.function.IntConsumer;
import java.util.function.Predicate;

/**
 * A query that selects all docs that do NOT belong in the current shards this query is executed on.
 * It can be used to split a shard into N shards marking every document that doesn't belong into the shard
 * as deleted. See {@link org.apache.lucene.index.IndexWriter#deleteDocuments(Query...)}
 */
final class ShardSplittingQuery extends Query {
    private final IndexMetadata indexMetadata;
    private final int shardId;

    ShardSplittingQuery(IndexMetadata indexMetadata, int shardId) {
        this.indexMetadata = indexMetadata;
        this.shardId = shardId;
    }

    @Override
    public Weight createWeight(IndexSearcher searcher, ScoreMode scoreMode, float boost) {
        return new ConstantScoreWeight(this, boost) {
            @Override
            public String toString() {
                return "weight(delete docs query)";
            }

            @Override
            public Scorer scorer(LeafReaderContext context) throws IOException {
                LeafReader leafReader = context.reader();
                FixedBitSet bitSet = new FixedBitSet(leafReader.maxDoc());
                Predicate<BytesRef> includeInShard = ref -> {
                    int targetShardId = OperationRouting.generateShardId(indexMetadata,
                        Uid.decodeId(ref.bytes, ref.offset, ref.length), null);
                    return shardId == targetShardId;
                };
                // this is the common case - no partitioning and no _routing values
                // in this case we also don't do anything special with regards to nested docs since we basically delete
                // by ID and parent and nested all have the same id.
                assert indexMetadata.isRoutingPartitionedIndex() == false;
                findSplitDocs(IdFieldMapper.NAME, includeInShard, leafReader, bitSet::set);
                return new ConstantScoreScorer(this, score(), scoreMode, new BitSetIterator(bitSet, bitSet.length()));
            }

            @Override
            public boolean isCacheable(LeafReaderContext ctx) {
                // This is not a regular query, let's not cache it. It wouldn't help
                // anyway.
                return false;
            }
        };
    }

    @Override
    public String toString(String field) {
        return "shard_splitting_query";
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        ShardSplittingQuery that = (ShardSplittingQuery) o;

        if (shardId != that.shardId) return false;
        return indexMetadata.equals(that.indexMetadata);
    }

    @Override
    public int hashCode() {
        int result = indexMetadata.hashCode();
        result = 31 * result + shardId;
        return classHash() ^ result;
    }

    private static void findSplitDocs(String idField, Predicate<BytesRef> includeInShard, LeafReader leafReader,
                                      IntConsumer consumer) throws IOException {
        Terms terms = leafReader.terms(idField);
        TermsEnum iterator = terms.iterator();
        BytesRef idTerm;
        PostingsEnum postingsEnum = null;
        while ((idTerm = iterator.next()) != null) {
            if (includeInShard.test(idTerm) == false) {
                postingsEnum = iterator.postings(postingsEnum);
                int doc;
                while ((doc = postingsEnum.nextDoc()) != DocIdSetIterator.NO_MORE_DOCS) {
                    consumer.accept(doc);
                }
            }
        }
    }

    /* this class is a stored fields visitor that reads _id and/or _routing from the stored fields which is necessary in the case
       of a routing partitioned index sine otherwise we would need to un-invert the _id and _routing field which is memory heavy */
    private final class Visitor extends StoredFieldVisitor {
        final LeafReader leafReader;
        private int leftToVisit = 2;
        private final BytesRef spare = new BytesRef();
        private String routing;
        private String id;

        Visitor(LeafReader leafReader) {
            this.leafReader = leafReader;
        }

        @Override
        public void binaryField(FieldInfo fieldInfo, byte[] value) throws IOException {
            switch (fieldInfo.name) {
                case IdFieldMapper.NAME:
                    id = Uid.decodeId(value);
                    break;
                default:
                    throw new IllegalStateException("Unexpected field: " + fieldInfo.name);
            }
        }

        @Override
        public void stringField(FieldInfo fieldInfo, byte[] value) throws IOException {
            throw new IllegalStateException("Unexpected field: " + fieldInfo.name);
        }

        @Override
        public Status needsField(FieldInfo fieldInfo) throws IOException {
            // we don't support 5.x so no need for the uid field
            switch (fieldInfo.name) {
                case IdFieldMapper.NAME:
                    leftToVisit--;
                    return Status.YES;
                default:
                    return leftToVisit == 0 ? Status.STOP : Status.NO;
            }
        }

        boolean matches(int doc) throws IOException {
            routing = id = null;
            leftToVisit = 2;
            leafReader.document(doc, this);
            assert id != null : "docID must not be null - we might have hit a nested document";
            int targetShardId = OperationRouting.generateShardId(indexMetadata, id, routing);
            return targetShardId != shardId;
        }
    }

    /**
     * This two phase iterator visits every live doc and selects all docs that don't belong into this
     * shard based on their id and routing value. This is only used in a routing partitioned index.
     */
    private static final class RoutingPartitionedDocIdSetIterator extends TwoPhaseIterator {
        private final Visitor visitor;

        RoutingPartitionedDocIdSetIterator(Visitor visitor) {
            super(DocIdSetIterator.all(visitor.leafReader.maxDoc())); // we iterate all live-docs
            this.visitor = visitor;
        }

        @Override
        public boolean matches() throws IOException {
            return visitor.matches(approximation.docID());
        }

        @Override
        public float matchCost() {
            return 42; // that's obvious, right?
        }
    }
}


