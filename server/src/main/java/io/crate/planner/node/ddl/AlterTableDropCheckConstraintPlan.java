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

package io.crate.planner.node.ddl;

import static io.crate.data.Row1.ROW_COUNT_UNKNOWN;

import io.crate.analyze.AnalyzedAlterTableDropCheckConstraint;
import io.crate.data.Row;
import io.crate.data.RowConsumer;
import io.crate.execution.ddl.tables.DropConstraintRequest;
import io.crate.execution.ddl.tables.TransportDropConstraint;
import io.crate.execution.support.OneRowActionListener;
import io.crate.planner.DependencyCarrier;
import io.crate.planner.Plan;
import io.crate.planner.PlannerContext;
import io.crate.planner.operators.SubQueryResults;

public class AlterTableDropCheckConstraintPlan implements Plan {

    private final AnalyzedAlterTableDropCheckConstraint dropCheckConstraint;

    public AlterTableDropCheckConstraintPlan(AnalyzedAlterTableDropCheckConstraint dropCheckConstraint) {
        this.dropCheckConstraint = dropCheckConstraint;
    }

    @Override
    public StatementType type() {
        return StatementType.DDL;
    }

    @Override
    public void executeOrFail(DependencyCarrier dependencies,
                              PlannerContext plannerContext,
                              RowConsumer consumer,
                              Row params,
                              SubQueryResults subQueryResults) {
        var request = new DropConstraintRequest(
            dropCheckConstraint.tableInfo().ident(),
            dropCheckConstraint.name()
        );

        dependencies.client().execute(TransportDropConstraint.ACTION, request)
            .whenComplete(new OneRowActionListener<>(consumer, _ -> ROW_COUNT_UNKNOWN));
    }
}
