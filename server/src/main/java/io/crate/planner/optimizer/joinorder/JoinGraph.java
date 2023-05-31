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

package io.crate.planner.optimizer.joinorder;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

import io.crate.analyze.relations.QuerySplitter;
import io.crate.expression.symbol.Symbol;
import io.crate.planner.operators.Collect;
import io.crate.planner.operators.HashJoin;
import io.crate.planner.operators.LogicalPlan;
import io.crate.planner.operators.LogicalPlanVisitor;
import io.crate.planner.optimizer.iterative.GroupReference;

public class JoinGraph {

    private final LogicalPlan root;
    private final List<LogicalPlan> nodes;
    private final Map<Integer, Set<Edge>> edges;

    public JoinGraph(LogicalPlan root, List<LogicalPlan> nodes, Map<Integer, Set<Edge>> edges) {
        this.root = root;
        this.nodes = nodes;
        this.edges = edges;
    }

    public JoinGraph joinWith(LogicalPlan root, JoinGraph other, Map<Integer, Set<Edge>> moreEdges) {
        for (LogicalPlan node : other.nodes) {
            assert !edges.containsKey(node) : "Nodes can not be in both graphs";
        }

        var newNodes = new ArrayList<LogicalPlan>();
        newNodes.addAll(nodes);
        newNodes.addAll(other.nodes);

        var newEdges = new HashMap<Integer, Set<Edge>>();
        newEdges.putAll(edges);
        newEdges.putAll(other.edges);
        newEdges.putAll(moreEdges);


        return new JoinGraph(root, newNodes, newEdges);
    }

    public List<LogicalPlan> nodes() {
        return nodes;
    }

    public Map<Integer, Set<Edge>> edges() {
        return edges;
    }

    public LogicalPlan root() {
        return root;
    }

    public static class Edge {
        final LogicalPlan targetNode;
        final Symbol source;
        final Symbol target;

        public Edge(LogicalPlan targetNode, Symbol source, Symbol target) {
            this.targetNode = targetNode;
            this.source = source;
            this.target = target;
        }
    }

    public static JoinGraph create(LogicalPlan plan, Function<LogicalPlan, LogicalPlan> resolvePlan) {
        var visitor = new Visitor(resolvePlan);
        var context = new HashMap<Symbol, LogicalPlan>();
        return plan.accept(visitor, context);
    }

    private static class Visitor extends LogicalPlanVisitor<Map<Symbol, LogicalPlan>, JoinGraph> {

        private final Function<LogicalPlan, LogicalPlan> resolvePlan;

        public Visitor(Function<LogicalPlan, LogicalPlan> resolvePlan) {
            this.resolvePlan = resolvePlan;
        }

        @Override
        public JoinGraph visitPlan(LogicalPlan logicalPlan, Map<Symbol, LogicalPlan> context) {
            return super.visitPlan(logicalPlan, context);
        }

        @Override
        public JoinGraph visitGroupReference(GroupReference groupReference, Map<Symbol, LogicalPlan> context) {
            var resolved = resolvePlan.apply(groupReference);
            return resolved.accept(this, context);
        }

        @Override
        public JoinGraph visitHashJoin(HashJoin joinPlan, Map<Symbol, LogicalPlan> context) {
            JoinGraph left = joinPlan.lhs().accept(this, context);
            JoinGraph right = joinPlan.rhs().accept(this, context);

            // find equi-join conditions such as `a.x = b.y` and create edges
            var split = QuerySplitter.split(joinPlan.joinCondition());
            var edges = new HashMap<Integer, Set<Edge>>();
            for (var entry : split.entrySet()) {
                if (entry.getKey().size() == 2) {
                    if (entry.getValue() instanceof io.crate.expression.symbol.Function f) {
                        var a = f.arguments().get(0);
                        var b = f.arguments().get(1);
                        edges.put(context.get(a).id(), Set.of(new Edge(context.get(b), a, b)));
                    }
                }
            }
            return left.joinWith(joinPlan, right, edges);
        }

        @Override
        public JoinGraph visitCollect(Collect collect, Map<Symbol, LogicalPlan> context) {
            for (Symbol output : collect.outputs()) {
                context.put(output, collect);
            }
            return new JoinGraph(collect, List.of(collect), Map.of());
        }
    }

}
