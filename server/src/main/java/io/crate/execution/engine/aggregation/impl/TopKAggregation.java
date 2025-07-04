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

package io.crate.execution.engine.aggregation.impl;


import static io.crate.metadata.functions.TypeVariableConstraint.typeVariable;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.apache.datasketches.common.Util;
import org.apache.datasketches.frequencies.ErrorType;
import org.apache.datasketches.frequencies.ItemsSketch;
import org.apache.datasketches.frequencies.LongsSketch;
import org.apache.datasketches.memory.Memory;
import org.apache.lucene.util.BytesRef;
import org.apache.lucene.util.NumericUtils;
import org.apache.lucene.util.RamUsageEstimator;
import org.elasticsearch.Version;
import org.elasticsearch.common.breaker.CircuitBreakingException;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.network.NetworkUtils;
import org.jetbrains.annotations.Nullable;

import io.crate.Streamer;
import io.crate.data.Input;
import io.crate.data.breaker.RamAccounting;
import io.crate.execution.engine.aggregation.AggregationFunction;
import io.crate.execution.engine.aggregation.DocValueAggregator;
import io.crate.execution.engine.aggregation.impl.templates.BinaryDocValueAggregator;
import io.crate.execution.engine.aggregation.impl.templates.SortedNumericDocValueAggregator;
import io.crate.expression.reference.doc.lucene.LuceneReferenceResolver;
import io.crate.expression.symbol.Literal;
import io.crate.memory.MemoryManager;
import io.crate.metadata.FunctionType;
import io.crate.metadata.Functions;
import io.crate.metadata.Reference;
import io.crate.metadata.Scalar;
import io.crate.metadata.doc.DocTableInfo;
import io.crate.metadata.functions.BoundSignature;
import io.crate.metadata.functions.Signature;
import io.crate.statistics.SketchStreamer;
import io.crate.types.ByteType;
import io.crate.types.DataType;
import io.crate.types.DataTypes;
import io.crate.types.DoubleType;
import io.crate.types.FloatType;
import io.crate.types.IntegerType;
import io.crate.types.IpType;
import io.crate.types.LongType;
import io.crate.types.ShortType;
import io.crate.types.StringType;
import io.crate.types.TimestampType;
import io.crate.types.TypeSignature;

public class TopKAggregation extends AggregationFunction<TopKAggregation.State, Map<String, Object>> {

    public static final String NAME = "topk";

    static final Signature DEFAULT_SIGNATURE =
        Signature.builder(NAME, FunctionType.AGGREGATE)
            .argumentTypes(TypeSignature.parse("V"))
            .returnType(DataTypes.UNTYPED_OBJECT.getTypeSignature())
            .features(Scalar.Feature.DETERMINISTIC)
            .typeVariableConstraints(typeVariable("V"))
            .build();

    static final Signature LIMIT_SIGNATURE =
        Signature.builder(NAME, FunctionType.AGGREGATE)
            .argumentTypes(TypeSignature.parse("V"),
                DataTypes.INTEGER.getTypeSignature())
            .returnType(DataTypes.UNTYPED_OBJECT.getTypeSignature())
            .features(Scalar.Feature.DETERMINISTIC)
            .typeVariableConstraints(typeVariable("V"))
            .build();

    static final Signature LIMIT_CAPACITY_SIGNATURE =
        Signature.builder(NAME, FunctionType.AGGREGATE)
            .argumentTypes(TypeSignature.parse("V"),
                DataTypes.INTEGER.getTypeSignature(),
                DataTypes.INTEGER.getTypeSignature())
            .returnType(DataTypes.UNTYPED_OBJECT.getTypeSignature())
            .features(Scalar.Feature.DETERMINISTIC)
            .typeVariableConstraints(typeVariable("V"))
            .build();

    static {
        DataTypes.register(StateType.ID, StateType::new);
    }

    public static void register(Functions.Builder builder) {
        builder.add(
            DEFAULT_SIGNATURE,
            TopKAggregation::new
        );

        builder.add(
            LIMIT_SIGNATURE,
            TopKAggregation::new
        );

        builder.add(
            LIMIT_CAPACITY_SIGNATURE,
            TopKAggregation::new
        );
    }

    private final Signature signature;
    private final BoundSignature boundSignature;
    private final DataType<?> argumentType;

    private static final int DEFAULT_LIMIT = 8;
    private static final int MAX_LIMIT = 5_000;
    private static final int DEFAULT_MAX_CAPACITY = 8192;

    private TopKAggregation(Signature signature, BoundSignature boundSignature) {
        this.signature = signature;
        this.boundSignature = boundSignature;
        DataType<?> type = boundSignature.argTypes().getFirst();

        // in `ProjectionBuilder#getAggregations()` a signature is built with argument of type: StateType
        // (when in AggregationMode: ITER_PARTIAL). In this case we need to extract and use the actual type
        // on which the topK runs on
        if (type instanceof StateType st) {
            this.argumentType = st.innerType;
        } else {
            this.argumentType = type;
        }
    }

    @Override
    public Signature signature() {
        return signature;
    }

    @Override
    public BoundSignature boundSignature() {
        return boundSignature;
    }


    @Nullable
    @Override
    public State newState(RamAccounting ramAccounting,
                          Version minNodeInCluster,
                          MemoryManager memoryManager) {
        return State.EMPTY;
    }

    @Override
    public State iterate(RamAccounting ramAccounting,
                         MemoryManager memoryManager,
                         State state,
                         Input<?>... args) throws CircuitBreakingException {
        Object value = args[0].value();
        if (state instanceof Empty) {
            if (args.length == 3) {
                Integer limit = (Integer) args[1].value();
                Integer capacity = (Integer) args[2].value();
                state = initState(ramAccounting, limit, capacity);
            } else if (args.length == 2) {
                // We have a limit provided by the user
                Integer limit = (Integer) args[1].value();
                state = initState(ramAccounting, limit, DEFAULT_MAX_CAPACITY);

            } else if (args.length == 1) {
                state = initState(ramAccounting, DEFAULT_LIMIT, DEFAULT_MAX_CAPACITY);
            }
        }
        state.update(value, argumentType);
        return state;
    }

    private static long calculateRamUsage(long maxMapSize) {
        // The internal memory space usage of item sketch will never exceed 18 * maxMapSize bytes, plus a small
        // constant number of additional bytes.
        // https://datasketches.apache.org/docs/Frequency/FrequentItemsOverview.html
        return maxMapSize * 18L;
    }

    @Override
    public State reduce(RamAccounting ramAccounting, State state1, State state2) {
        return state1.merge(state2);
    }

    @Override
    public Map<String, Object> terminatePartial(RamAccounting ramAccounting, State state) {
        return state.result(argumentType);
    }

    public DataType<?> partialType() {
        return new StateType(argumentType);
    }

    @Nullable
    @Override
    public DocValueAggregator<?> getDocValueAggregator(LuceneReferenceResolver referenceResolver,
                                                       List<Reference> aggregationReferences,
                                                       DocTableInfo table,
                                                       Version shardCreatedVersion,
                                                       List<Literal<?>> optionalParams) {
        Reference reference = getAggReference(aggregationReferences);
        if (reference == null) {
            return null;
        }

        if (optionalParams.isEmpty()) {
            return getDocValueAggregator(reference, DEFAULT_LIMIT, DEFAULT_MAX_CAPACITY);
        }

        // topk(ref) -> aggregationReferences[ref] optionalParams[null]
        if (optionalParams.size() == 1 && optionalParams.getFirst() == null) {
            return getDocValueAggregator(reference, DEFAULT_LIMIT, DEFAULT_MAX_CAPACITY);
        }

        // topk(ref, limit) -> aggregationReferences[ref, null] optionalParams[null, limit]
        if (optionalParams.size() == 2) {
            Literal<?> limitLiteral = optionalParams.getLast();
            int limit = limitLiteral == null ? DEFAULT_LIMIT : (int) limitLiteral.value();
            return getDocValueAggregator(reference, limit, DEFAULT_MAX_CAPACITY);
        }

        // topk(ref, limit, capacity) -> aggregationReferences[ref, null, null] optionalParams[null, limit, capacity]
        if (optionalParams.size() == 3) {
            Literal<?> limitLiteral = optionalParams.get(1);
            Literal<?> capacityLiteral = optionalParams.get(2);
            int limit = limitLiteral == null ? DEFAULT_LIMIT : (int) limitLiteral.value();
            int capacity = capacityLiteral == null ? DEFAULT_MAX_CAPACITY : (int) capacityLiteral.value();
            return getDocValueAggregator(reference, limit, capacity);
        }
        return null;
    }

    @Nullable
    private DocValueAggregator<?> getDocValueAggregator(Reference ref, int limit, int capacity) {
        DataType<?> type = ref.valueType();
        if (supportedByLongSketch(type)) {
            return new SortedNumericDocValueAggregator<>(
                ref.storageIdent(),
                (ramAccounting, _, _) -> topKLongState(ramAccounting, limit, capacity),
                (_, values, state) -> state.update(values.nextValue(), type));
        } else if (type.id() == StringType.ID) {
            return new BinaryDocValueAggregator<>(
                ref.storageIdent(),
                (ramAccounting, _, _) -> topKState(ramAccounting, limit, capacity),
                (_, values, state) -> {
                    long ord = values.nextOrd();
                    BytesRef value = values.lookupOrd(ord);
                    state.update(value.utf8ToString(), type);
                });
        } else if (type.id() == IpType.ID) {
            return new BinaryDocValueAggregator<>(
                ref.storageIdent(),
                (ramAccounting, _, _) -> topKState(ramAccounting, limit, capacity),
                (_, values, state) -> {
                    long ord = values.nextOrd();
                    BytesRef value = values.lookupOrd(ord);
                    state.update(NetworkUtils.formatIPBytes(value), type);
                });
        }
        return null;
    }

    sealed interface State {

        Empty EMPTY = new Empty();

        Map<String, Object> result(DataType<?> dataType);

        State merge(State other);

        void update(Object value, DataType<?> dataType);

        void update(long value, DataType<?> dataType);

        void writeTo(StreamOutput out, DataType<?> innerType) throws IOException;

        static State fromStream(StreamInput in, DataType<?> innerType) throws IOException {
            int id = in.readByte();
            switch (id) {
                case TopKState.ID -> {
                    return new TopKState(in, innerType);
                }
                case TopKLongState.ID -> {
                    return new TopKLongState(in);
                }
                default -> {
                    return State.EMPTY;
                }
            }
        }
    }

    static final class Empty implements State {

        static final int ID = 0;

        @Override
        public Map<String, Object> result(DataType<?> datatype) {
            return Map.of();
        }

        @Override
        public State merge(State other) {
            return other;
        }

        @Override
        public void update(Object value, DataType<?> dataType) {
            throw new UnsupportedOperationException("Empty state does not support updates");
        }

        @Override
        public void update(long value, DataType<?> dataType) {
            throw new UnsupportedOperationException("Empty state does not support updates");
        }

        @Override
        public void writeTo(StreamOutput out, DataType<?> innerType) throws IOException {
            out.writeByte((byte) ID);
        }
    }

    static final class TopKState implements State {

        static long SHALLOW_SIZE = RamUsageEstimator.shallowSizeOfInstance(TopKState.class);
        static final int ID = 1;

        private final ItemsSketch<Object> sketch;
        private final int limit;

        TopKState(ItemsSketch<Object> sketch, int limit) {
            this.sketch = sketch;
            this.limit = limit;
        }

        @SuppressWarnings({"rawtypes", "unchecked"})
        TopKState(StreamInput in, DataType<?> innerType) throws IOException {
            this.limit = in.readInt();
            SketchStreamer streamer = new SketchStreamer(innerType.streamer());
            this.sketch = ItemsSketch.getInstance(Memory.wrap(in.readByteArray()), streamer);
        }

        public Map<String, Object> result(DataType<?> dataType) {
            if (sketch.isEmpty()) {
                return Map.of();
            }
            ItemsSketch.Row<Object>[] frequentItems = sketch.getFrequentItems(ErrorType.NO_FALSE_NEGATIVES);
            int limit = Math.min(frequentItems.length, this.limit);
            var frequencies = new ArrayList<Map<String, Object>>(limit);
            for (int i = 0; i < limit; i++) {
                var item = frequentItems[i];
                frequencies.add(Map.of(
                        "item", item.getItem(),
                        "estimate", item.getEstimate(),
                        "lower_bound", item.getLowerBound(),
                        "upper_bound", item.getUpperBound()
                    )
                );
            }
            return Map.of(
                "maximum_error", sketch.getMaximumError(),
                "frequencies", frequencies
            );
        }

        @Override
        public State merge(State other) {
            if (other instanceof Empty) {
                return this;
            } else if (other instanceof TopKState otherTopk) {
                return new TopKState(this.sketch.merge(otherTopk.sketch), limit);
            }
            throw new IllegalArgumentException("Cannot merge state");
        }

        @Override
        public void update(Object value, DataType<?> dataType) {
            sketch.update(value);
        }

        @Override
        public void update(long value, DataType<?> dataType) {
            sketch.update(value);
        }

        @Override
        @SuppressWarnings({"rawtypes", "unchecked"})
        public void writeTo(StreamOutput out, DataType<?> innerType) throws IOException {
            out.writeByte((byte) ID);
            out.writeInt(limit);
            SketchStreamer streamer = new SketchStreamer(innerType.streamer());
            out.writeByteArray(sketch.toByteArray(streamer));
        }

    }

    static final class TopKLongState implements State {

        static long SHALLOW_SIZE = RamUsageEstimator.shallowSizeOfInstance(TopKLongState.class);
        static final int ID = 2;

        private final LongsSketch sketch;
        private final int limit;

        TopKLongState(LongsSketch sketch, int limit) {
            this.sketch = sketch;
            this.limit = limit;
        }

        TopKLongState(StreamInput in) throws IOException {
            this.limit = in.readInt();
            this.sketch = LongsSketch.getInstance(Memory.wrap(in.readByteArray()));
        }

        @Override
        public Map<String, Object> result(DataType<?> dataType) {
            if (sketch.isEmpty()) {
                return Map.of();
            }
            LongsSketch.Row[] frequentItems = sketch.getFrequentItems(ErrorType.NO_FALSE_NEGATIVES);
            int limit = Math.min(frequentItems.length, this.limit);
            var frequencies = new ArrayList<Map<String, Object>>();
            for (int i = 0; i < limit; i++) {
                var item = frequentItems[i];
                frequencies.add(Map.of(
                    "item", toObject(dataType, item.getItem()),
                    "estimate", item.getEstimate(),
                    "lower_bound", item.getLowerBound(),
                    "upper_bound", item.getUpperBound()
                    )
                );
            }
            return Map.of("maximum_error", sketch.getMaximumError(),
                "frequencies", frequencies
            );
        }

        @Override
        public State merge(State other) {
            if (other instanceof Empty) {
                return this;
            } else if (other instanceof TopKLongState otherTopK) {
                return new TopKLongState(this.sketch.merge(otherTopK.sketch), limit);
            }
            throw new IllegalArgumentException("Cannot merge state");
        }

        @Override
        public void update(Object value, DataType<?> dataType) {
            sketch.update(toLong(dataType, value));
        }

        @Override
        public void update(long value, DataType<?> dataType) {
            sketch.update(value);
        }

        @Override
        public void writeTo(StreamOutput out, DataType<?> innerType) throws IOException {
            out.writeByte((byte) ID);
            out.writeInt(limit);
            out.writeByteArray(sketch.toByteArray());
        }

        private static long toLong(DataType<?> type, Object o) {
            return switch (type.id()) {
                case LongType.ID, TimestampType.ID_WITHOUT_TZ, TimestampType.ID_WITH_TZ -> (Long) o;
                case DoubleType.ID -> NumericUtils.doubleToSortableLong((Double) o);
                case FloatType.ID -> (long) NumericUtils.floatToSortableInt((Float) o);
                case IntegerType.ID -> ((Integer) o).longValue();
                case ShortType.ID -> ((Short) o).longValue();
                case ByteType.ID -> ((Byte) o).longValue();
                default -> throw new IllegalArgumentException("Type cannot be converted to long");
            };
        }

        private static Object toObject(DataType<?> type, long o) {
            return switch (type.id()) {
                case LongType.ID, TimestampType.ID_WITHOUT_TZ, TimestampType.ID_WITH_TZ -> o;
                case DoubleType.ID -> NumericUtils.sortableLongToDouble(o);
                case FloatType.ID -> NumericUtils.sortableIntToFloat((int) o);
                case IntegerType.ID -> (int) o;
                case ShortType.ID -> (short) o;
                case ByteType.ID -> (byte) o;
                default -> throw new IllegalArgumentException("Long value cannot be converted");
            };
        }
    }

    private static boolean supportedByLongSketch(DataType<?> type) {
        return switch (type.id()) {
            case LongType.ID,
                 DoubleType.ID,
                 FloatType.ID,
                 IntegerType.ID,
                 ShortType.ID,
                 ByteType.ID,
                 TimestampType.ID_WITHOUT_TZ,
                 TimestampType.ID_WITH_TZ -> true;
            default -> false;
        };
    }

    private State initState(RamAccounting ramAccounting, int limit, int capacity) {
        if (limit <= 0 || limit > MAX_LIMIT) {
            throw new IllegalArgumentException(
                "Limit parameter for topk must be between 0 and 10_000. Got: " + limit);
        }
        if (!Util.isIntPowerOf2(capacity)) {
            throw new IllegalArgumentException(
                "Capacity parameter must be a positive integer-power of 2. Got: " + capacity);
        }
        if (limit >= capacity) {
            throw new IllegalArgumentException(
                "Limit parameter for topk must be less than capacity parameter. Got limit: "
                    + limit + " capacity: " + capacity);
        }
        if (supportedByLongSketch(argumentType)) {
            return topKLongState(ramAccounting, limit, capacity);
        } else {
            return topKState(ramAccounting, limit, capacity);
        }
    }

    private TopKState topKState(RamAccounting ramAccounting, int limit, int capacity) {
        ramAccounting.addBytes(calculateRamUsage(capacity) + TopKState.SHALLOW_SIZE);
        return new TopKState(new ItemsSketch<>(capacity), limit);
    }

    private TopKLongState topKLongState(RamAccounting ramAccounting, int limit, int capacity) {
        ramAccounting.addBytes(calculateRamUsage(capacity) + TopKLongState.SHALLOW_SIZE);
        return new TopKLongState(new LongsSketch(capacity), limit);
    }

    static final class StateType extends DataType<State> implements Streamer<State> {

        public static final int ID = 4232;
        private final DataType<?> innerType;

        public StateType(DataType<?> innerType) {
            this.innerType = innerType;
        }

        public StateType(StreamInput streamInput) throws IOException {
            this.innerType = DataTypes.fromStream(streamInput);
        }

        @Override
        public void writeTo(StreamOutput out) throws IOException {
            DataTypes.toStream(innerType, out);
        }

        @Override
        public int id() {
            return ID;
        }

        @Override
        public Precedence precedence() {
            return Precedence.CUSTOM;
        }

        @Override
        public String getName() {
            return "topk_state";
        }

        @Override
        public Streamer<State> streamer() {
            return this;
        }

        @Override
        public State sanitizeValue(Object value) {
            return (State) value;
        }

        @Override
        public State readValueFrom(StreamInput in) throws IOException {
            return State.fromStream(in, innerType);
        }

        @Override
        public void writeValueTo(StreamOutput out, State state) throws IOException {
            state.writeTo(out, innerType);
        }

        @Override
        public long valueBytes(State value) {
            throw new UnsupportedOperationException("valueSize is not implemented for TopKStateType");
        }

        @Override
        public int compare(State s1, State s2) {
            return 0;
        }
    }
}
