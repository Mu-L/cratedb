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


import java.util.function.Function;

import org.elasticsearch.Version;
import org.jetbrains.annotations.Nullable;

import io.crate.execution.dml.ValueIndexer;
import io.crate.expression.reference.doc.lucene.SourceParser;
import io.crate.metadata.ColumnIdent;
import io.crate.metadata.IndexType;
import io.crate.metadata.Reference;
import io.crate.metadata.RelationName;

public abstract class StorageSupport<T> {

    private final boolean docValuesDefault;
    private final boolean supportsDocValuesOff;

    @Nullable
    private final EqQuery<T> eqQuery;

    StorageSupport(StorageSupport<T> base) {
        this(base.docValuesDefault, base.supportsDocValuesOff, base.eqQuery);
    }

    StorageSupport(boolean docValuesDefault,
                   boolean supportsDocValuesOff,
                   @Nullable EqQuery<T> eqQuery) {
        this.docValuesDefault = docValuesDefault;
        this.supportsDocValuesOff = supportsDocValuesOff;
        this.eqQuery = eqQuery;
    }

    public boolean getComputedDocValuesDefault(@Nullable IndexType indexType) {
        return docValuesDefault && indexType != IndexType.FULLTEXT;
    }


    /**
     * Creates a valueIndexer
     */
    public abstract ValueIndexer<? super T> valueIndexer(
        RelationName table,
        Reference ref,
        Function<ColumnIdent, Reference> getRef);

    /**
     * Decode a value from bytes in a stored field
     */
    public T decode(ColumnIdent column, SourceParser sourceParser, Version tableVersion, byte[] bytes) {
        throw new UnsupportedOperationException("decodeFromBytes not supported");
    }

    /**
     * Decode a value from a long in a stored field
     */
    public T decode(long input) {
        throw new UnsupportedOperationException("decodeFromLong not supported");
    }

    /**
     * Decode a value from an int in a stored field
     */
    public T decode(int input) {
        throw new UnsupportedOperationException("decodeFromInt not supported");
    }

    /**
     * @return {@code true} if values should always be loaded from stored fields
     */
    public boolean retrieveFromStoredFields() {
        return false;
    }

    public boolean canBeIndexed() {
        return true;
    }

    public boolean docValuesDefault() {
        return docValuesDefault;
    }

    public boolean supportsDocValuesOff() {
        return supportsDocValuesOff;
    }

    @Nullable
    public EqQuery<T> eqQuery() {
        return eqQuery;
    }
}
