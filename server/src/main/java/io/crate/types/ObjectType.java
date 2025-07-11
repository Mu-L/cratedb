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

package io.crate.types;

import static io.crate.types.DataTypes.ALLOWED_CONVERSIONS;
import static io.crate.types.DataTypes.UNDEFINED;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.function.Supplier;

import org.apache.lucene.search.Query;
import org.apache.lucene.util.Accountable;
import org.apache.lucene.util.RamUsageEstimator;
import org.elasticsearch.Version;
import org.elasticsearch.common.io.stream.ByteBufferStreamInput;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.xcontent.DeprecationHandler;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.common.xcontent.json.JsonXContent;
import org.jetbrains.annotations.Nullable;

import io.crate.Streamer;
import io.crate.common.collections.Lists;
import io.crate.exceptions.ConversionException;
import io.crate.execution.dml.ObjectIndexer;
import io.crate.execution.dml.ValueIndexer;
import io.crate.expression.reference.doc.lucene.SourceParser;
import io.crate.metadata.ColumnIdent;
import io.crate.metadata.Reference;
import io.crate.metadata.RelationName;
import io.crate.metadata.settings.SessionSettings;
import io.crate.sql.tree.ColumnDefinition;
import io.crate.sql.tree.ColumnPolicy;
import io.crate.sql.tree.ColumnType;
import io.crate.sql.tree.Expression;
import io.crate.sql.tree.ObjectColumnType;

public class ObjectType extends DataType<Map<String, Object>> implements Streamer<Map<String, Object>> {

    public static final ObjectType UNTYPED = new ObjectType(Map.of(), ColumnPolicy.DYNAMIC);
    public static final int ID = 12;
    public static final String NAME = "object";
    private static final StorageSupport<Map<String, Object>> STORAGE = new StorageSupport<>(false, false, null) {

        @Override
        public ValueIndexer<Map<String, Object>> valueIndexer(RelationName table,
                                                              Reference ref,
                                                              Function<ColumnIdent, Reference> getRef) {
            return new ObjectIndexer(table, ref, getRef);
        }

        @Override
        public Map<String, Object> decode(ColumnIdent column, SourceParser sourceParser, Version tableVersion, byte[] bytes) {
            try (StreamInput in = new ByteBufferStreamInput(ByteBuffer.wrap(bytes))) {
                in.setVersion(tableVersion);
                return in.readMap(StreamInput::readString, StreamInput::readGenericValue);
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }
    };

    public static class Builder {

        private final LinkedHashMap<String, DataType<?>> innerTypesBuilder = new LinkedHashMap<>();
        private final ColumnPolicy columnPolicy;

        private Builder(ColumnPolicy columnPolicy) {
            this.columnPolicy = columnPolicy;
        }

        public Builder setInnerType(String key, DataType<?> innerType) {
            var exists = innerTypesBuilder.put(key, innerType);
            if (exists != null) {
                throw new IllegalArgumentException("Column \"" + key + "\" specified more than once");
            }
            return this;
        }

        public Builder mergeInnerType(String key, DataType<?> innerType, BiFunction<DataType<?>, DataType<?>, DataType<?>> remappingFunction) {
            innerTypesBuilder.merge(key, innerType, remappingFunction);
            return this;
        }

        public ObjectType build() {
            return new ObjectType(Collections.unmodifiableMap(innerTypesBuilder), columnPolicy);
        }
    }

    public static Builder of(ColumnPolicy columnPolicy) {
        return new Builder(columnPolicy);
    }

    private final Map<String, DataType<?>> innerTypes;
    private final ColumnPolicy columnPolicy;

    private ObjectType(Map<String, DataType<?>> innerTypes, ColumnPolicy columnPolicy) {
        this.innerTypes = innerTypes;
        this.columnPolicy = Objects.requireNonNull(columnPolicy);
    }

    public Map<String, DataType<?>> innerTypes() {
        return innerTypes;
    }

    public DataType<?> innerType(String key) {
        return innerTypes.getOrDefault(key, UndefinedType.INSTANCE);
    }

    public DataType<?> innerType(List<String> path) {
        if (path.isEmpty()) {
            return DataTypes.UNDEFINED;
        }
        DataType<?> innerType = DataTypes.UNDEFINED;
        ObjectType currentObject = this;
        int arrayNesting = 0;
        for (int i = 0; i < path.size(); i++) {
            innerType = currentObject.innerType(path.get(i));
            while (innerType instanceof ArrayType<?> arrayType) {
                arrayNesting++;
                innerType = arrayType.innerType();
            }
            if (innerType instanceof ObjectType objectType) {
                currentObject = objectType;
            } else if (i < path.size() - 1) {
                return DataTypes.UNDEFINED;
            }
        }
        for (int i = 0; i < arrayNesting; i++) {
            innerType = new ArrayType<>(innerType);
        }
        return innerType;
    }

    @Override
    public int id() {
        return ID;
    }

    @Override
    public Precedence precedence() {
        return Precedence.OBJECT;
    }

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public Streamer<Map<String, Object>> streamer() {
        return this;
    }

    @Override
    public Map<String, Object> implicitCast(Object value) throws IllegalArgumentException, ClassCastException {
        return convert(value, DataType::implicitCast);
    }

    @Override
    public Map<String, Object> explicitCast(Object value, SessionSettings sessionSettings) throws IllegalArgumentException, ClassCastException {
        return convert(value, (dataType, val) -> dataType.explicitCast(val, sessionSettings));
    }

    @Override
    public Map<String, Object> sanitizeValue(Object value) {
        return convert(value, DataType::sanitizeValue);
    }

    @Override
    public Map<String, Object> sanitizeValueLenient(Object value) {
        try {
            return convert(value, DataType::sanitizeValueLenient);
        } catch (Exception e) {
            return null;
        }
    }

    @Override
    @SuppressWarnings("unchecked")
    public Map<String, Object> valueForInsert(Map<String, Object> value) {
        return convert(value, (dataType, v) -> ((DataType<Object>) dataType).valueForInsert(v));
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> convert(Object value,
                                        BiFunction<DataType<?>, Object, Object> innerType) {
        if (value instanceof String str) {
            value = mapFromJSON(str);
        }
        Map<String, Object> map = (Map<String, Object>) value;
        if (map == null || innerTypes == null) {
            return map;
        }

        HashMap<String, Object> newMap = (map instanceof LinkedHashMap<String, Object>) ? new LinkedHashMap<>(map) : new HashMap<>(map);
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            String key = entry.getKey();
            DataType<?> targetType = innerType(key);
            Object sourceValue = entry.getValue();
            Object convertedInnerValue;
            try {
                convertedInnerValue = innerType.apply(targetType, sourceValue);
            } catch (ClassCastException | IllegalArgumentException e) {
                throw ConversionException.forObjectChild(key, sourceValue, targetType);
            }
            newMap.put(key, convertedInnerValue);
        }
        return newMap;
    }

    private static Map<String,Object> mapFromJSON(String value) {
        try {
            XContentParser parser = JsonXContent.JSON_XCONTENT.createParser(
                NamedXContentRegistry.EMPTY,
                DeprecationHandler.THROW_UNSUPPORTED_OPERATION,
                value
            );
            return parser.map();
        } catch (IOException e) {
            var conversionException = new ConversionException(value, UNTYPED);
            conversionException.addSuppressed(e);
            throw conversionException;
        }
    }

    @Override
    public int compare(Map<String, Object> val1, Map<String, Object> val2) {
        return MapComparator.compareMaps(val1, val2);
    }

    @Override
    @SuppressWarnings("rawtypes")
    public Map<String, Object> readValueFrom(StreamInput in) throws IOException {
        if (in.readBoolean()) {
            int size = in.readInt();
            LinkedHashMap<String, Object> m = LinkedHashMap.newLinkedHashMap(size);
            for (int i = 0; i < size; i++) {
                String key = in.readString();
                DataType innerType = innerType(key);
                Object val = innerType.streamer().readValueFrom(in);
                m.put(key, val);
            }
            return m;
        }
        return null;
    }

    @Override
    public boolean isConvertableTo(DataType<?> o, boolean explicitCast) {
        Set<Integer> conversions = ALLOWED_CONVERSIONS.getOrDefault(id(), Set.of());
        if (conversions.contains(o.id())) {
            return true;
        }
        if (explicitCast && o.id() == DataTypes.STRING.id()) {
            return true;
        }

        if (ArrayType.unnest(o) == UNDEFINED) {
            // We allow to override an empty array type (inner type is undefined) with an object type.
            // See {@link SqlMappingTest#test_dynamic_null_array_get_by_pk}
            return true;
        }

        // Do not check the inner types here as this will result in a generic object type cast error if inner types
        // aren't convertible.
        // Let's fall through, so the {@link #cast(Object, boolean)} method will be called. It checks the inner types
        // and provide a more specific error message including the original value (which isn't available here).
        // See {@link SqlMappingTest#testInsertObjectIntoString}

        return o.id() == id();
    }

    @Override
    DataType<?> merge(DataType<?> other, ColumnPolicy columnPolicy) {
        if (other instanceof ObjectType o) {
            return merge(this, o, DataTypes::merge, columnPolicy);
        } else {
            return super.merge(other, columnPolicy);
        }
    }

    public static ObjectType merge(ObjectType left,
                                   ObjectType right,
                                   BiFunction<DataType<?>, DataType<?>, DataType<?>> remappingFunction,
                                   ColumnPolicy columnPolicy) {
        ObjectType.Builder mergedObjectBuilder = ObjectType.of(columnPolicy);
        for (var e : left.innerTypes().entrySet()) {
            mergedObjectBuilder.setInnerType(e.getKey(), e.getValue().withColumnPolicy(columnPolicy));
        }
        for (var e : right.innerTypes().entrySet()) {
            mergedObjectBuilder.mergeInnerType(e.getKey(), e.getValue(), remappingFunction);
        }
        return mergedObjectBuilder.build();
    }

    public ObjectType withoutChild(String childColumn) {
        LinkedHashMap<String, DataType<?>> newInnerTypes = new LinkedHashMap<>(innerTypes);
        newInnerTypes.remove(childColumn);
        return new ObjectType(Collections.unmodifiableMap(newInnerTypes), columnPolicy);
    }

    public ObjectType withChild(String childColumn, DataType<?> type) {
        LinkedHashMap<String, DataType<?>> newInnerTypes = new LinkedHashMap<>(innerTypes);
        newInnerTypes.put(childColumn, type);
        return new ObjectType(Collections.unmodifiableMap(newInnerTypes), columnPolicy);
    }

    @Override
    public boolean equals(Object o) {
        if (!super.equals(o)) {
            return false;
        }
        ObjectType that = (ObjectType) o;
        if (!Objects.equals(innerTypes, that.innerTypes)) {
            return false;
        }
        return columnPolicy == that.columnPolicy;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + innerTypes.hashCode();
        return prime * result + columnPolicy.hashCode();
    }

    @Override
    @SuppressWarnings({"unchecked", "rawtypes"})
    public void writeValueTo(StreamOutput out, Map<String, Object> v) throws IOException {
        if (v == null) {
            out.writeBoolean(false);
        } else {
            out.writeBoolean(true);
            out.writeInt(v.size());
            for (Map.Entry<String, Object> entry : v.entrySet()) {
                String key = entry.getKey();
                out.writeString(key);
                DataType innerType = innerTypes.getOrDefault(key, UndefinedType.INSTANCE);
                innerType.streamer().writeValueTo(out, innerType.implicitCast(entry.getValue()));
            }
        }
    }

    public ObjectType(StreamInput in) throws IOException {
        int numTypes = in.readVInt();
        // recover the order it was streamed out
        LinkedHashMap<String, DataType<?>> builder = LinkedHashMap.newLinkedHashMap(numTypes);
        for (int i = 0; i < numTypes; i++) {
            String key = in.readString();
            DataType<?> type = DataTypes.fromStream(in);
            builder.put(key, type);
        }
        innerTypes = Collections.unmodifiableMap(builder);
        if (in.getVersion().onOrAfter(Version.V_5_10_0)) {
            columnPolicy = in.readEnum(ColumnPolicy.class);
        } else {
            columnPolicy = ColumnPolicy.DYNAMIC;
        }
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeVInt(innerTypes.size());
        for (Map.Entry<String, DataType<?>> entry : innerTypes.entrySet()) {
            out.writeString(entry.getKey());
            DataTypes.toStream(entry.getValue(), out);
        }
        if (out.getVersion().onOrAfter(Version.V_5_10_0)) {
            out.writeEnum(columnPolicy);
        }
    }

    @Override
    public TypeSignature getTypeSignature() {
        TypeSignature stringTypeSignature = StringType.INSTANCE.getTypeSignature();
        ArrayList<TypeSignature> parameters = new ArrayList<>(innerTypes.size() * 2);
        for (var innerTypeKeyValue : innerTypes.entrySet()) {
            // all keys are of type 'text'
            parameters.add(stringTypeSignature);
            var innerType = innerTypeKeyValue.getValue();
            parameters.add(
                new ParameterTypeSignature(innerTypeKeyValue.getKey(), innerType.getTypeSignature()));
        }
        return new TypeSignature(NAME, parameters);
    }

    @Override
    public List<DataType<?>> getTypeParameters() {
        ArrayList<DataType<?>> parameters = new ArrayList<>(innerTypes.size() * 2);
        for (var type : innerTypes.values()) {
            // all keys are of type 'text'
            parameters.add(StringType.INSTANCE);
            parameters.add(type);
        }
        return parameters;
    }

    @Override
    public ColumnType<Expression> toColumnType(@Nullable Supplier<List<ColumnDefinition<Expression>>> convertChildColumn) {
        if (convertChildColumn == null) {
            return new ObjectColumnType<>(
                columnPolicy,
                Lists.map(innerTypes.entrySet(), e -> new ColumnDefinition<>(
                    e.getKey(),
                    e.getValue().toColumnType(convertChildColumn),
                    List.of()
                ))
            );
        } else {
            return new ObjectColumnType<>(columnPolicy, convertChildColumn.get());
        }
    }

    @Override
    public StorageSupport<Map<String, Object>> storageSupport() {
        return STORAGE;
    }

    @Override
    public long valueBytes(Map<String, Object> map) {
        if (map == null) {
            return RamUsageEstimator.NUM_BYTES_OBJECT_HEADER;
        }
        return sizeOfMap(map);
    }

    /**
     * Similar to {@link RamUsageEstimator#sizeOfMap(Map)}
     * but not limited with depth = 1.
     */
    private static long sizeOfMap(Map<?, ?> map) {
        if (map == null) {
            return 0;
        }
        long size = RamUsageEstimator.shallowSizeOf(map);
        long sizeOfEntry = -1;
        for (Map.Entry<?, ?> entry : map.entrySet()) {
            if (sizeOfEntry == -1) {
                sizeOfEntry = RamUsageEstimator.shallowSizeOf(entry);
            }
            size += sizeOfEntry;

            // In most cases key has type String but for ignored object can be another type.
            size += sizeOfObject(entry.getKey());
            size += sizeOfObject(entry.getValue());
        }
        return RamUsageEstimator.alignObjectSize(size);
    }

    /**
     * Similar to {@link RamUsageEstimator#sizeOfObject(Object)}
     * but sizeOfMap and sizeOfCollection are replaced by custom methods without depth limitation
     */
    private static long sizeOfObject(Object o) {
        if (o == null) {
            return 0;
        }
        long size;
        if (o instanceof Accountable) {
            size = ((Accountable) o).ramBytesUsed();
        } else if (o instanceof String) {
            size = RamUsageEstimator.sizeOf((String) o);
        } else if (o instanceof boolean[]) {
            size = RamUsageEstimator.sizeOf((boolean[]) o);
        } else if (o instanceof byte[]) {
            size = RamUsageEstimator.sizeOf((byte[]) o);
        } else if (o instanceof char[]) {
            size = RamUsageEstimator.sizeOf((char[]) o);
        } else if (o instanceof double[]) {
            size = RamUsageEstimator.sizeOf((double[]) o);
        } else if (o instanceof float[]) {
            size = RamUsageEstimator.sizeOf((float[]) o);
        } else if (o instanceof int[]) {
            size = RamUsageEstimator.sizeOf((int[]) o);
        } else if (o instanceof Integer) {
            size = RamUsageEstimator.sizeOf((Integer) o);
        } else if (o instanceof Long) {
            size = RamUsageEstimator.sizeOf((Long) o);
        } else if (o instanceof long[]) {
            size = RamUsageEstimator.sizeOf((long[]) o);
        } else if (o instanceof short[]) {
            size = RamUsageEstimator.sizeOf((short[]) o);
        } else if (o instanceof String[]) {
            size = RamUsageEstimator.sizeOf((String[]) o);
        } else if (o instanceof Query) {
            size = RamUsageEstimator.sizeOf((Query) o, RamUsageEstimator.UNKNOWN_DEFAULT_RAM_BYTES_USED);
        } else if (o instanceof Map<?, ?> map) {
            size = sizeOfMap(map);
        } else if (o instanceof Collection<?> collection) {
            size = sizeOfCollection(collection);
        } else {
            size = RamUsageEstimator.UNKNOWN_DEFAULT_RAM_BYTES_USED;
        }
        return size;
    }

    /**
     * Similar to {@link RamUsageEstimator#sizeOfCollection(Collection)}
     * but not limited with depth = 1.
     */
    private static long sizeOfCollection(Collection<?> collection) {
        if (collection == null) {
            return 0;
        }
        long size = RamUsageEstimator.shallowSizeOf(collection);
        // assume array-backed collection and add per-object references
        size += RamUsageEstimator.NUM_BYTES_ARRAY_HEADER + (long) collection.size() * RamUsageEstimator.NUM_BYTES_OBJECT_REF;
        for (Object o : collection) {
            size += sizeOfObject(o);
        }
        return RamUsageEstimator.alignObjectSize(size);
    }

    @Override
    public long ramBytesUsed() {
        long bytes = RamUsageEstimator.NUM_BYTES_OBJECT_HEADER; // innerTypes field
        for (var entry : innerTypes.entrySet()) {
            String childName = entry.getKey();
            DataType<?> childType = entry.getValue();
            bytes += RamUsageEstimator.sizeOf(childName);
            bytes += childType.ramBytesUsed();
        }
        return bytes + RamUsageEstimator.sizeOf(ColumnPolicy.DYNAMIC.ordinal());
    }

    @Override
    public ColumnPolicy columnPolicy() {
        return columnPolicy;
    }

    @Override
    public DataType<Map<String, Object>> withColumnPolicy(ColumnPolicy columnPolicy) {
        if (this.columnPolicy == columnPolicy) {
            return this;
        }
        var objType = ObjectType.of(columnPolicy);
        for (var entry : innerTypes.entrySet()) {
            objType.setInnerType(entry.getKey(), entry.getValue().withColumnPolicy(columnPolicy));
        }
        return objType.build();
    }
}
