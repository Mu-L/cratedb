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

package io.crate.analyze;

import java.util.function.Consumer;
import java.util.function.Supplier;

import io.crate.analyze.relations.AnalyzedRelation;
import io.crate.expression.symbol.Symbol;

public class AnalyzedCreateTableAs implements AnalyzedStatement {

    private final AnalyzedCreateTable analyzedCreateTable;
    private final Supplier<AnalyzedInsertStatement> postponedInsertAnalysis;
    private final AnalyzedRelation sourceRelation;

    public AnalyzedCreateTableAs(AnalyzedCreateTable analyzedCreateTable,
                                 AnalyzedRelation sourceRelation,
                                 Supplier<AnalyzedInsertStatement> postponedInsertAnalysis) {
        this.analyzedCreateTable = analyzedCreateTable;
        this.sourceRelation = sourceRelation;
        this.postponedInsertAnalysis = postponedInsertAnalysis;
    }

    public AnalyzedRelation sourceRelation() {
        return sourceRelation;
    }


    public AnalyzedCreateTable analyzedCreateTable() {
        return analyzedCreateTable;
    }

    public AnalyzedInsertStatement analyzePostponedInsertStatement() {
        return this.postponedInsertAnalysis.get();
    }

    @Override
    public <C, R> R accept(AnalyzedStatementVisitor<C, R> visitor, C context) {
        return visitor.visitCreateTableAs(this, context);
    }

    @Override
    public boolean isWriteOperation() {
        return true;
    }

    @Override
    public void visitSymbols(Consumer<? super Symbol> consumer) {
    }
}
