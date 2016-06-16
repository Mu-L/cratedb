/*
 * Licensed to CRATE Technology GmbH ("Crate") under one or more contributor
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

package io.crate.analyze.relations;

import com.google.common.base.Optional;
import com.google.common.collect.Iterables;
import com.google.common.collect.Multimap;
import io.crate.analyze.*;
import io.crate.analyze.expressions.ExpressionAnalysisContext;
import io.crate.analyze.expressions.ExpressionAnalyzer;
import io.crate.analyze.relations.select.SelectAnalyzer;
import io.crate.analyze.symbol.*;
import io.crate.analyze.symbol.Literal;
import io.crate.analyze.symbol.format.SymbolFormatter;
import io.crate.analyze.symbol.format.SymbolPrinter;
import io.crate.analyze.validator.GroupBySymbolValidator;
import io.crate.analyze.validator.HavingSymbolValidator;
import io.crate.analyze.validator.SemanticSortValidator;
import io.crate.exceptions.AmbiguousColumnAliasException;
import io.crate.metadata.FunctionInfo;
import io.crate.metadata.TableIdent;
import io.crate.metadata.doc.DocTableInfo;
import io.crate.metadata.table.Operation;
import io.crate.metadata.table.TableInfo;
import io.crate.metadata.tablefunctions.TableFunctionImplementation;
import io.crate.operation.operator.AndOperator;
import io.crate.planner.consumer.OrderByWithAggregationValidator;
import io.crate.sql.tree.*;
import io.crate.types.DataTypes;
import org.elasticsearch.cluster.ClusterService;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.inject.Singleton;

import javax.annotation.Nullable;
import java.util.*;

@Singleton
public class RelationAnalyzer extends DefaultTraversalVisitor<AnalyzedRelation, RelationAnalysisContext> {

    private final static AggregationSearcher AGGREGATION_SEARCHER = new AggregationSearcher();

    private final ClusterService clusterService;
    private final AnalysisMetaData analysisMetaData;
    private static final EnumSet<Join.Type> ALLOWED_JOIN_TYPES = EnumSet.of(Join.Type.CROSS, Join.Type.INNER);

    @Inject
    public RelationAnalyzer(ClusterService clusterService, AnalysisMetaData analysisMetaData) {
        this.clusterService = clusterService;
        this.analysisMetaData = analysisMetaData;
    }


    public AnalyzedRelation analyze(Node node, RelationAnalysisContext relationAnalysisContext) {
        return process(node, relationAnalysisContext);
    }

    public AnalyzedRelation analyze(Node node, Analysis analysis) {
        return analyze(node, new RelationAnalysisContext(analysis.parameterContext(), analysisMetaData));
    }

    @Override
    protected AnalyzedRelation visitQuery(Query node, RelationAnalysisContext context) {
        return process(node.getQueryBody(), context);
    }

    @Override
    protected AnalyzedRelation visitUnion(Union node, RelationAnalysisContext context) {
        throw new UnsupportedOperationException("UNION is not supported");
    }

    @Override
    protected AnalyzedRelation visitJoin(Join node, RelationAnalysisContext context) {
        if (!ALLOWED_JOIN_TYPES.contains(node.getType())) {
            throw new UnsupportedOperationException("Explicit " + node.getType().name() + " join syntax is not supported");
        }
        process(node.getLeft(), context);
        process(node.getRight(), context);

        Optional<JoinCriteria> optCriteria = node.getCriteria();
        if (optCriteria.isPresent()) {
            JoinCriteria joinCriteria = optCriteria.get();
            if (joinCriteria instanceof JoinOn) {
                context.addJoinExpression(((JoinOn) joinCriteria).getExpression());
            } else {
                throw new UnsupportedOperationException(String.format(Locale.ENGLISH, "join criteria %s not supported",
                        joinCriteria.getClass().getSimpleName()));
            }
        }
        return null;
    }

    @Override
    protected AnalyzedRelation visitQuerySpecification(QuerySpecification node, RelationAnalysisContext context) {
        if (node.getFrom() == null) {
            throw new IllegalArgumentException("FROM clause is missing.");
        }
        for (Relation relation : node.getFrom()) {
            process(relation, context);
        }
        ExpressionAnalysisContext expressionAnalysisContext = context.expressionAnalysisContext();
        WhereClause whereClause = analyzeWhere(node.getWhere(), context);

        SelectAnalyzer.SelectAnalysis selectAnalysis = SelectAnalyzer.analyzeSelect(node.getSelect(), context);

        List<Symbol> groupBy = analyzeGroupBy(selectAnalysis, node.getGroupBy(), context);

        if (!node.getGroupBy().isEmpty() || expressionAnalysisContext.hasAggregates) {
            ensureNonAggregatesInGroupBy(selectAnalysis.outputSymbols(), groupBy);
        }
        boolean isDistinct = false;
        if (node.getSelect().isDistinct() && groupBy.isEmpty()) {
            groupBy = rewriteGlobalDistinct(selectAnalysis.outputSymbols());
            isDistinct = true;
        }
        if (groupBy != null && groupBy.isEmpty()){
            groupBy = null;
        }

        QuerySpec querySpec = new QuerySpec()
                .orderBy(analyzeOrderBy(selectAnalysis, node.getOrderBy(), context,
                    expressionAnalysisContext.hasAggregates || groupBy != null, isDistinct))
                .having(analyzeHaving(node.getHaving(), groupBy, context))
                .limit(context.expressionAnalyzer().integerFromExpression(node.getLimit()))
                .offset(context.expressionAnalyzer().integerFromExpression(node.getOffset()))
                .outputs(selectAnalysis.outputSymbols())
                .where(whereClause)
                .groupBy(groupBy)
                .hasAggregates(expressionAnalysisContext.hasAggregates);

        if (context.sources().size() == 1) {
            AnalyzedRelation source = Iterables.getOnlyElement(context.sources().values());
            QueriedTableRelation relation;
            if (source instanceof DocTableRelation) {
                relation = new QueriedDocTable(
                        (DocTableRelation) source, selectAnalysis.outputNames(), querySpec);
            } else if (source instanceof TableRelation) {
                relation =  new QueriedTable((TableRelation) source, selectAnalysis.outputNames(), querySpec);
            } else {
                throw new UnsupportedOperationException("Only tables are allowed in the FROM clause, got: " + source);
            }
            relation.normalize(analysisMetaData);
            return relation;
        }
        // TODO: implement multi table selects
        // once this is used .normalize should for this class needs to be handled here too
        return new MultiSourceSelect(
                context.sources(),
                selectAnalysis.outputNames(),
                querySpec
        );
    }

    @Nullable
    private List<Symbol> rewriteGlobalDistinct(List<Symbol> outputSymbols) {
        List<Symbol> groupBy = new ArrayList<>(outputSymbols.size());
        for (Symbol symbol : outputSymbols) {
            if (!isAggregate(symbol)) {
                GroupBySymbolValidator.validate(symbol);
                groupBy.add(symbol);
            }
        }
        return groupBy;
    }

    private void ensureNonAggregatesInGroupBy(List<Symbol> outputSymbols, List<Symbol> groupBy) throws IllegalArgumentException {
        for (Symbol output : outputSymbols) {
            if (groupBy == null || !groupBy.contains(output)) {
                if (!isAggregate(output)) {
                    throw new IllegalArgumentException(
                            SymbolFormatter.format("column '%s' must appear in the GROUP BY clause " +
                                                   "or be used in an aggregation function", output));
                }
            }
        }
    }

    private boolean isAggregate(Symbol s) {
        return AGGREGATION_SEARCHER.process(s, null);
    }

    static class AggregationSearcher extends SymbolVisitor<Void, Boolean> {

        @Override
        protected Boolean visitSymbol(Symbol symbol, Void context) {
            return false;
        }

        @Override
        public Boolean visitFunction(Function symbol, Void context) {
            if (symbol.info().type() == FunctionInfo.Type.AGGREGATE) {
                return true;
            } else {
                for (Symbol argument : symbol.arguments()) {
                    if (process(argument, context)) {
                        return true;
                    }
                }
            }
            return false;
        }

        @Override
        public Boolean visitAggregation(Aggregation symbol, Void context) {
            return true;
        }
    }

    @Nullable
    private OrderBy analyzeOrderBy(SelectAnalyzer.SelectAnalysis selectAnalysis,
                                   List<SortItem> orderBy,
                                   RelationAnalysisContext context,
                                   boolean hasAggregatesOrGrouping,
                                   boolean isDistinct) {
        int size = orderBy.size();
        if (size == 0) {
            return null;
        }
        List<Symbol> symbols = new ArrayList<>(size);
        boolean[] reverseFlags = new boolean[size];
        Boolean[] nullsFirst = new Boolean[size];

        for (int i = 0; i < size; i++) {
            SortItem sortItem = orderBy.get(i);
            Expression sortKey = sortItem.getSortKey();
            Symbol symbol = symbolFromSelectOutputReferenceOrExpression(sortKey, selectAnalysis, "ORDER BY", context);
            SemanticSortValidator.validate(symbol);
            if (hasAggregatesOrGrouping) {
                OrderByWithAggregationValidator.validate(symbol, selectAnalysis.outputSymbols(), isDistinct);
            }

            symbols.add(symbol);
            switch (sortItem.getNullOrdering()) {
                case FIRST:
                    nullsFirst[i] = true;
                    break;
                case LAST:
                    nullsFirst[i] = false;
                    break;
                case UNDEFINED:
                    nullsFirst[i] = null;
                    break;
            }
            reverseFlags[i] = sortItem.getOrdering() == SortItem.Ordering.DESCENDING;
        }
        return new OrderBy(symbols, reverseFlags, nullsFirst);
    }

    private List<Symbol> analyzeGroupBy(SelectAnalyzer.SelectAnalysis selectAnalysis, List<Expression> groupBy,
                                        RelationAnalysisContext context) {
        List<Symbol> groupBySymbols = new ArrayList<>(groupBy.size());
        for (Expression expression : groupBy) {
            Symbol symbol = symbolFromSelectOutputReferenceOrExpression(
                    expression, selectAnalysis, "GROUP BY", context);
            GroupBySymbolValidator.validate(symbol);
            groupBySymbols.add(symbol);
        }
        return groupBySymbols;
    }

    private HavingClause analyzeHaving(Optional<Expression> having, List<Symbol> groupBy, RelationAnalysisContext context) {
        if (having.isPresent()) {
            if (!context.expressionAnalysisContext().hasAggregates && (groupBy == null || groupBy.isEmpty())) {
                throw new IllegalArgumentException("HAVING clause can only be used in GROUP BY or global aggregate queries");
            }
            Symbol symbol = context.expressionAnalyzer().convert(having.get(), context.expressionAnalysisContext());
            HavingSymbolValidator.validate(symbol, groupBy);
            return new HavingClause(context.expressionAnalyzer().normalize(symbol));
        }
        return null;
    }

    private WhereClause analyzeWhere(Optional<Expression> where, RelationAnalysisContext context) {
        List<Expression> joinExpressions = context.joinExpressions();
        if (!where.isPresent() && joinExpressions.isEmpty()) {
            return WhereClause.MATCH_ALL;
        }
        Symbol query;
        if (where.isPresent()) {
            query = context.expressionAnalyzer().convert(where.get(), context.expressionAnalysisContext());
        } else {
            query = Literal.BOOLEAN_TRUE;
        }
        if (!joinExpressions.isEmpty()) {
            for (Expression joinExpression : joinExpressions) {
                Symbol joinCondition = context.expressionAnalyzer().convert(joinExpression, context.expressionAnalysisContext());
                query = new Function(AndOperator.INFO, Arrays.asList(query, joinCondition));
            }
        }
        query = context.expressionAnalyzer().normalize(query);
        return new WhereClause(query);
    }


    /**
     * <h2>resolve expression by also taking alias and ordinal-reference into account</h2>
     *
     * <p>
     * in group by or order by clauses it is possible to reference anything in the
     * select list by using a number or alias
     * </p>
     *
     * These are allowed:
     * <pre>
     *     select name as n  ... order by n
     *     select name  ... order by 1
     *     select name ... order by other_column
     * </pre>
     */
    private Symbol symbolFromSelectOutputReferenceOrExpression(Expression expression,
                                                               SelectAnalyzer.SelectAnalysis selectAnalysis,
                                                               String clause,
                                                               RelationAnalysisContext context) {
        Symbol symbol;
        if (expression instanceof QualifiedNameReference) {
            List<String> parts = ((QualifiedNameReference) expression).getName().getParts();
            if (parts.size() == 1) {
                symbol = getOneOrAmbiguous(selectAnalysis.outputMultiMap(), Iterables.getOnlyElement(parts));
                if (symbol != null) {
                    return symbol;
                }
            }
        }
        symbol = context.expressionAnalyzer().convert(expression, context.expressionAnalysisContext());
        if (symbol.symbolType().isValueSymbol()) {
            Literal longLiteral;
            try {
                longLiteral = io.crate.analyze.symbol.Literal.convert(symbol, DataTypes.LONG);
            } catch (ClassCastException | IllegalArgumentException e) {
                throw new UnsupportedOperationException(String.format(Locale.ENGLISH,
                        "Cannot use %s in %s clause", SymbolPrinter.INSTANCE.printSimple(symbol), clause));
            }
            symbol = ordinalOutputReference(selectAnalysis.outputSymbols(), longLiteral, clause);
        }
        return symbol;
    }

    private Symbol ordinalOutputReference(List<Symbol> outputSymbols, Literal longLiteral, String clauseName) {
        assert longLiteral.valueType().equals(DataTypes.LONG) : "longLiteral must have valueType long";
        int idx = ((Long) longLiteral.value()).intValue() - 1;
        if (idx < 0) {
            throw new IllegalArgumentException(String.format(Locale.ENGLISH,
                    "%s position %s is not in select list", clauseName, idx + 1));
        }
        try {
            return outputSymbols.get(idx);
        } catch (IndexOutOfBoundsException e) {
            throw new IllegalArgumentException(String.format(Locale.ENGLISH,
                    "%s position %s is not in select list", clauseName, idx + 1));
        }
    }

    @Nullable
    private Symbol getOneOrAmbiguous(Multimap<String, Symbol> selectList, String key) throws AmbiguousColumnAliasException {
        Collection<Symbol> symbols = selectList.get(key);
        if (symbols.size() > 1) {
            throw new AmbiguousColumnAliasException(key);
        }
        if (symbols.isEmpty()) {
            return null;
        }
        return symbols.iterator().next();
    }

    @Override
    protected AnalyzedRelation visitAliasedRelation(AliasedRelation node, RelationAnalysisContext context) {
        AnalyzedRelation childRelation = process(node.getRelation(),
                new RelationAnalysisContext(context.parameterContext(), analysisMetaData));
        context.addSourceRelation(node.getAlias(), childRelation);
        return childRelation;
    }

    @Override
    protected AnalyzedRelation visitTable(Table node, RelationAnalysisContext context) {
        TableInfo tableInfo = analysisMetaData.schemas().getTableInfo(
                TableIdent.of(node, context.parameterContext().defaultSchema()));
        Operation.blockedRaiseException(tableInfo, context.currentOperation());
        AnalyzedRelation tableRelation;
        // Dispatching of doc relations is based on the returned class of the schema information.
        if (tableInfo instanceof DocTableInfo){
            tableRelation = new DocTableRelation((DocTableInfo) tableInfo);
        } else {
            tableRelation = new TableRelation(tableInfo);
        }
        context.addSourceRelation(tableInfo.ident().schema(), tableInfo.ident().name(), tableRelation);
        return tableRelation;
    }

    @Override
    public AnalyzedRelation visitTableFunction(TableFunction node, RelationAnalysisContext context) {
        ExpressionAnalyzer expressionAnalyzer = new ExpressionAnalyzer(
                analysisMetaData, context.parameterContext(), new FieldProvider() {
            @Override
            public Symbol resolveField(QualifiedName qualifiedName, boolean forWrite) {
                throw new UnsupportedOperationException("Can only resolve literals");
            }

            @Override
            public Symbol resolveField(QualifiedName qualifiedName, @Nullable List path, boolean forWrite) {
                throw new UnsupportedOperationException("Can only resolve literals");
            }
        }, null);

        List<Symbol> arguments = new ArrayList<>(node.arguments().size());
        for (Expression expression : node.arguments()) {
            Symbol symbol = expressionAnalyzer.convert(expression, context.expressionAnalysisContext());
            arguments.add(symbol);
        }
        TableFunctionImplementation tableFunction = analysisMetaData.functions().getTableFunctionSafe(node.name());
        TableInfo tableInfo = tableFunction.createTableInfo(clusterService, Symbols.extractTypes(arguments));
        Operation.blockedRaiseException(tableInfo, context.currentOperation());
        TableRelation tableRelation = new TableFunctionRelation(tableInfo, node.name(), arguments);
        context.addSourceRelation(node.name(), tableRelation);
        return tableRelation;
    }
}
