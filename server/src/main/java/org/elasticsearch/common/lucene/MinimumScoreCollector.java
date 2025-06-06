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

package org.elasticsearch.common.lucene;

import java.io.IOException;

import org.apache.lucene.index.LeafReaderContext;
import org.apache.lucene.search.Collector;
import org.apache.lucene.search.LeafCollector;
import org.apache.lucene.search.Scorable;
import org.apache.lucene.search.ScoreCachingWrappingScorer;
import org.apache.lucene.search.ScoreMode;
import org.apache.lucene.search.Weight;

public class MinimumScoreCollector<T extends Collector> implements Collector {

    private final T collector;
    private final float minimumScore;

    public MinimumScoreCollector(T collector, float minimumScore) {
        this.collector = collector;
        this.minimumScore = minimumScore;
    }

    public T delegate() {
        return collector;
    }

    @Override
    public LeafCollector getLeafCollector(LeafReaderContext context) throws IOException {
        LeafCollector delegateLeafCollector = collector.getLeafCollector(context);
        return ScoreCachingWrappingScorer.wrap(new LeafCollector() {

            Scorable scorer;

            @Override
            public void setScorer(Scorable scorer) throws IOException {
                this.scorer = scorer;
                delegateLeafCollector.setScorer(scorer);
            }

            @Override
            public void collect(int doc) throws IOException {
                if (this.scorer.score() >= minimumScore) {
                    delegateLeafCollector.collect(doc);
                }
            }
        });
    }

    @Override
    public void setWeight(Weight weight) {
        collector.setWeight(weight);
    }

    @Override
    public ScoreMode scoreMode() {
        return ScoreMode.COMPLETE;
    }

}
