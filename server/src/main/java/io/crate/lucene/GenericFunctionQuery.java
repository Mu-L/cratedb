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

package io.crate.lucene;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;

import org.apache.lucene.index.DocValues;
import org.apache.lucene.index.LeafReader;
import org.apache.lucene.index.LeafReaderContext;
import org.apache.lucene.search.ConstantScoreScorer;
import org.apache.lucene.search.DocIdSetIterator;
import org.apache.lucene.search.Explanation;
import org.apache.lucene.search.IndexSearcher;
import org.apache.lucene.search.Query;
import org.apache.lucene.search.QueryVisitor;
import org.apache.lucene.search.ScoreMode;
import org.apache.lucene.search.Scorer;
import org.apache.lucene.search.ScorerSupplier;
import org.apache.lucene.search.TwoPhaseIterator;
import org.apache.lucene.search.Weight;
import org.apache.lucene.util.Bits;

import io.crate.data.Input;
import io.crate.execution.engine.fetch.ReaderContext;
import io.crate.expression.InputCondition;
import io.crate.expression.reference.doc.lucene.LuceneCollectorExpression;
import io.crate.expression.symbol.Function;
import io.crate.metadata.Reference;

/**
 * Query implementation which filters docIds by evaluating {@code condition} on each docId to verify if it matches.
 *
 * This query is very slow.
 */
public class GenericFunctionQuery extends Query {

    private final Function function;
    private final LuceneCollectorExpression<?>[] expressions;
    private final Input<Boolean> condition;
    private final Runnable raiseIfKilled;

    GenericFunctionQuery(Function function,
                         Collection<? extends LuceneCollectorExpression<?>> expressions,
                         Input<Boolean> condition,
                         Runnable raiseIfKilled) {
        this.function = function;
        // inner loop iterates over expressions - call toArray to avoid iterator allocations
        this.expressions = expressions.toArray(new LuceneCollectorExpression[0]);
        this.condition = condition;
        this.raiseIfKilled = raiseIfKilled;
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof GenericFunctionQuery that && function.equals(that.function);
    }

    @Override
    public int hashCode() {
        return function.hashCode();
    }

    @Override
    public Weight createWeight(IndexSearcher searcher, ScoreMode scoreMode, float boost) throws IOException {
        return new Weight(this) {
            @Override
            public boolean isCacheable(LeafReaderContext ctx) {
                if (!function.isDeterministic()) {
                    return false;
                }
                var fields = new ArrayList<String>();
                function.visit(Reference.class, ref -> fields.add(ref.storageIdent()));
                return DocValues.isCacheable(ctx, fields.toArray(new String[0]));
            }

            @Override
            public Explanation explain(LeafReaderContext context, int doc) throws IOException {
                final Scorer s = scorer(context);
                final boolean match;
                final TwoPhaseIterator twoPhase = s.twoPhaseIterator();
                if (twoPhase == null) {
                    match = s.iterator().advance(doc) == doc;
                } else {
                    match = twoPhase.approximation().advance(doc) == doc && twoPhase.matches();
                }
                if (match) {
                    assert s.score() == 0f : "score must be 0";
                    return Explanation.match(0f, "Match on id " + doc);
                } else {
                    return Explanation.match(0f, "No match on id " + doc);
                }
            }

            @Override
            public ScorerSupplier scorerSupplier(LeafReaderContext context) {
                return new ScorerSupplier() {
                    @Override
                    public Scorer get(long leadCost) throws IOException {
                        for (LuceneCollectorExpression<?> expression : expressions) {
                            expression.setNextReader(new ReaderContext(context));
                        }
                        var twoPhaseIterator = new FilteredTwoPhaseIterator(
                            context.reader(),
                            condition,
                            expressions,
                            raiseIfKilled
                        );
                        return new ConstantScoreScorer(0f, scoreMode, twoPhaseIterator);
                    }

                    @Override
                    public long cost() {
                        return context.reader().maxDoc();
                    }
                };
            }
        };
    }

    @Override
    public void visit(QueryVisitor visitor) {
    }

    @Override
    public String toString(String field) {
        return function.toString();
    }

    private static class FilteredTwoPhaseIterator extends TwoPhaseIterator {

        private final Input<Boolean> condition;
        private final LuceneCollectorExpression<?>[] expressions;
        private final Bits liveDocs;
        private final Runnable raiseIfKilled;

        FilteredTwoPhaseIterator(LeafReader reader,
                                 Input<Boolean> condition,
                                 LuceneCollectorExpression<?>[] expressions,
                                 Runnable raiseIfKilled) {
            super(DocIdSetIterator.all(reader.maxDoc()));
            this.liveDocs = reader.getLiveDocs() == null
                                ? new Bits.MatchAllBits(reader.maxDoc())
                                : reader.getLiveDocs();
            this.condition = condition;
            this.expressions = expressions;
            this.raiseIfKilled = raiseIfKilled;
        }

        @Override
        public boolean matches() throws IOException {
            int doc = approximation.docID();
            if (!liveDocs.get(doc)) {
                return false;
            }
            raiseIfKilled.run();
            for (LuceneCollectorExpression<?> expression : expressions) {
                expression.setNextDocId(doc);
            }
            return InputCondition.matches(condition);
        }

        @Override
        public float matchCost() {
            // Arbitrary number, we don't have a way to get the cost of the condition
            return 10;
        }
    }
}
