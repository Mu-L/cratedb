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

package io.crate.common.collections;

import java.util.AbstractList;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.ListIterator;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.RandomAccess;
import java.util.SequencedSet;
import java.util.StringJoiner;
import java.util.function.Function;
import java.util.stream.Collector;
import java.util.stream.Collectors;

import org.jetbrains.annotations.Nullable;

public final class Lists {

    private Lists() {
    }

    @SuppressWarnings("unchecked")
    public static <T> List<T> of(Iterable<? extends T> items) {
        if (items instanceof Collection<?> collection) {
            return new ArrayList<>((Collection<T>) collection);
        }
        ArrayList<T> result = new ArrayList<>();
        for (var item : items) {
            result.add(item);
        }
        return result;
    }

    /**
     * Create a new list that contains the elements of both arguments
     */
    public static <T> List<T> concat(Collection<? extends T> list1, Collection<? extends T> list2) {
        ArrayList<T> list = new ArrayList<>(list1.size() + list2.size());
        list.addAll(list1);
        list.addAll(list2);
        return list;
    }

    public static <T> List<T> concat(Collection<? extends T> list1, T item) {
        ArrayList<T> xs = new ArrayList<>(list1.size() + 1);
        xs.addAll(list1);
        xs.add(item);
        return xs;
    }

    public static <T> List<T> concat(T item, Collection<? extends T> list1) {
        ArrayList<T> xs = new ArrayList<>(list1.size() + 1);
        xs.add(item);
        xs.addAll(list1);
        return xs;
    }

    @SafeVarargs
    public static final <T> List<T> concat(T first, T ... tail) {
        ArrayList<T> result = new ArrayList<>(1 + tail.length);
        result.add(first);
        for (int i = 0; i < tail.length; i++) {
            result.add(tail[i]);
        }
        return result;
    }

    @SafeVarargs
    public static final <T> List<T> concat(T first, T second, T ... tail) {
        ArrayList<T> result = new ArrayList<>(2 + tail.length);
        result.add(first);
        result.add(second);
        for (int i = 0; i < tail.length; i++) {
            result.add(tail[i]);
        }
        return result;
    }

    public static <T> List<T> concatUnique(List<? extends T> list1, Collection<? extends T> list2) {
        List<T> result = new ArrayList<>(list1.size() + list2.size());
        result.addAll(list1);
        for (T item : list2) {
            if (!list1.contains(item)) {
                result.add(item);
            }
        }
        return result;
    }

    public static SequencedSet<?> flattenUnique(Iterable<?> items) {
        LinkedHashSet<Object> result = new LinkedHashSet<>();
        for (var element : items) {
            if (element instanceof Iterable<?> l) {
                result.addAll(flattenUnique(l));
            } else {
                result.add(element);
            }
        }
        return result;
    }

    /**
     * Compares two {@link Collection}s for equality of their members by exact order and size.
     */
    public static boolean equals(Collection<?> list1, Collection<?> list2) {
        if (list1 == list2) {
            return true;
        }
        if (list1 == null || list2 == null) {
            return false;
        }
        if (list1.size() != list2.size()) {
            return false;
        }

        Iterator<?> it1 = list1.iterator();
        Iterator<?> it2 = list2.iterator();
        while (it1.hasNext() && it2.hasNext()) {
            if (!Objects.equals(it1.next(), it2.next())) {
                return false;
            }
        }
        return true;
    }

    /**
     * Create a copy of the given list with {@code mapper} applied on each item.
     * Opposed to {@link java.util.stream.Stream#map(Function)} / {@link Collectors#toList()} this minimizes allocations.
     */
    public static <I, O> List<O> map(Collection<I> list, Function<? super I, ? extends O> mapper) {
        if (list.isEmpty()) {
            return List.of();
        }
        ArrayList<O> copy = new ArrayList<>(list.size());
        for (I item : list) {
            copy.add(mapper.apply(item));
        }
        return copy;
    }

    /**
     * Like `map` but ensures that the same list is returned if no elements changed.
     * But is a view onto the original list and applies the mapper lazy on a need basis.
     */
    public static <I, O> List<O> mapLazy(List<I> list, Function<? super I, ? extends O> mapper) {
        return new LazyMapList<>(list, mapper);
    }


    /**
     * Like `map` but ensures that the same list is returned if no elements changed
     */
    public static <T> List<T> mapIfChange(List<T> list, Function<? super T, ? extends T> mapper) {
        if (list.isEmpty()) {
            return list;
        }
        ArrayList<T> copy = new ArrayList<>(list.size());
        boolean changed = false;
        for (T item : list) {
            T mapped = mapper.apply(item);
            changed = changed || item != mapped;
            copy.add(mapped);
        }
        return changed ? copy : list;
    }

    /**
     * Return the first element of a list or raise an IllegalArgumentException if there are more than 1 items.
     *
     * Similar to Guava's com.google.common.collect.Iterables#getOnlyElement(Iterable), but avoids an iterator allocation
     *
     * @throws NoSuchElementException If the list is empty
     * @throws IllegalArgumentException If the list has more than 1 element
     */
    public static <T> T getOnlyElement(List<T> items) {
        switch (items.size()) {
            case 0:
                throw new NoSuchElementException("List is empty");

            case 1:
                return items.get(0);

            default:
                throw new IllegalArgumentException("Expected 1 element, got: " + items.size());
        }
    }

    public static <O, I> List<O> mapTail(O head, List<I> tail, Function<I, O> mapper) {
        ArrayList<O> list = new ArrayList<>(tail.size() + 1);
        list.add(head);
        for (I input : tail) {
            list.add(mapper.apply(input));
        }
        return list;
    }

    /**
     * Finds the first non peer element in the provided list of items between the begin and end indexes.
     * Two items are peers if the provided comparator designates them as equals.
     * @return the position of the first item that's not equal with the item on the `begin` index in the list of items.
     */
    public static <T> int findFirstNonPeer(List<T> items, int begin, int end, @Nullable Comparator<T> cmp) {
        if (cmp == null || (begin + 1) >= end) {
            return end;
        }
        T fst = items.get(begin);
        if (cmp.compare(fst, items.get(begin + 1)) != 0) {
            return begin + 1;
        }
        /*
         * Adapted binarySearch algorithm to find the first non peer (instead of the first match)
         * This depends on there being at least some EQ values;
         * Whenever we find a EQ pair we check if the following element isn't EQ anymore.
         *
         * E.g.
         *
         * i:     0  1  2  3  4  5  6  7
         * rows: [1, 1, 1, 1, 4, 4, 5, 6]
         *        ^ [1  1  1  4  4  5  6]
         *        +-----------^
         *           cmp: -1
         *        1 [1  1  1  4] 4  5  6
         *        ^     ^
         *        +-----+
         *           cmp: 0 --> cmp (mid +1) != 0 --> false
         *        1  1  1 [1  4] 4  5  6
         *        ^        ^
         *        +--------+
         *           cmp: 0 --> cmp (mid +1) != 0 --> true
         */
        int low = begin + 1;
        int high = end;
        while (low <= high) {
            int mid = (low + high) >>> 1;
            T t = items.get(mid);
            int cmpResult = cmp.compare(fst, t);
            if (cmpResult == 0) {
                int next = mid + 1;
                if (next == high || cmp.compare(fst, items.get(next)) != 0) {
                    return next;
                } else {
                    low = next;
                }
            } else if (cmpResult < 0) {
                high = mid;
            } else {
                low = mid;
            }
        }
        return end;
    }

    /**
     * Finds the first peer, in order of appearance in the items list, of the item at the given index.
     * If the provided comparator is null this will return 0 (all items are peers when no comparator is specified).
     * If the provided item has no peers amongst the items that appear before it, or if it is the first item in the
     * list, this will return the itemIdx.
     */
    public static <T> int findFirstPreviousPeer(List<T> items, int itemIdx, @Nullable Comparator<T> cmp) {
        if (cmp == null) {
            return 0;
        }

        int firstPeer = itemIdx;
        T item = items.get(itemIdx);
        for (int i = itemIdx - 1; i >= 0; i--) {
            if (cmp.compare(item, items.get(i)) == 0) {
                firstPeer = i;
            } else {
                break;
            }
        }
        return firstPeer;
    }

    /**
     * Finds the first item that's less than or equal to the probe in the slice of the sortedItems that starts with the index
     * specified by @param itemIdx, according to the provided comparator.
     * @return the index of the first LTE item, or -1 if there isn't any (eg. probe is less than all items)
     */
    public static <T> int findFirstLTEProbeValue(List<T> sortedItems,
                                                 int upperBoundary,
                                                 int itemIdx,
                                                 T probe,
                                                 Comparator<T> cmp) {
        int start = itemIdx;
        int end = upperBoundary - 1;

        int firstLTEProbeIdx = -1;
        while (start <= end) {
            int mid = (start + end) >>> 1;
            // Move to left side if mid is greater than probe
            if (cmp.compare(sortedItems.get(mid), probe) > 0) {
                end = mid - 1;
            } else {
                firstLTEProbeIdx = mid;
                start = mid + 1;
            }
        }
        return firstLTEProbeIdx;
    }

    /**
     * Finds the first item that's greater than or equal to the probe in the slice of the sortedItems that ends with the index
     * specified by @param itemIdx, according to the provided comparator.
     * @return the index of the first GTE item, or -1 if there isn't any (eg. probe is greater than all items)
     */
    public static <T> int findFirstGTEProbeValue(List<T> sortedItems, int lowerBoundary, int itemIdx, T probe, Comparator<T> cmp) {
        int start = lowerBoundary;
        int end = itemIdx - 1;

        int firstGTEProbeIdx = -1;
        while (start <= end) {
            int mid = (start + end) >>> 1;
            // Move to right side if mid is less than probe
            if (cmp.compare(sortedItems.get(mid), probe) < 0) {
                start = mid + 1;
            } else {
                firstGTEProbeIdx = mid;
                end = mid - 1;
            }
        }
        return firstGTEProbeIdx;
    }

    /**
     * Less garbage producing alternative to
     * {@link java.util.stream.Stream#map(Function)} → {@link java.util.stream.Stream#collect(Collector)} with a {@link Collectors#joining(CharSequence)} collector.
     */
    public static <T> String joinOn(String delimiter, List<? extends T> items, Function<? super T, String> mapper) {
        StringJoiner joiner = new StringJoiner(delimiter);
        for (int i = 0; i < items.size(); i++) {
            joiner.add(mapper.apply(items.get(i)));
        }
        return joiner.toString();
    }

    /**
     * Same as {@link #joinOn(String, List, Function)} but uses iterator loop instead for random access on List
     */
    public static <T> String joinOn(String delimiter, Iterable<? extends T> items, Function<? super T, String> mapper) {
        StringJoiner joiner = new StringJoiner(delimiter);
        for (T item : items) {
            joiner.add(mapper.apply(item));
        }
        return joiner.toString();
    }


    /**
    * {@code LazyMapList} is a wrapper around a list that lazily applies
    * the {@code mapper} {@code Function} on each item when it is accessed.
    */
    static class LazyMapList<I, O> extends AbstractList<O> implements RandomAccess {

        private final List<I> list;
        private final Function<? super I, ? extends O> mapper;

        LazyMapList(List<I> list, Function<? super I, ? extends O> mapper) {
            this.list = list;
            this.mapper = mapper;
        }

        @Override
        public O get(int index) {
            return mapper.apply(list.get(index));
        }

        @Override
        public int size() {
            return list.size();
        }
    }

    /**
     * Return a rotated view of the given list with the given distance.
     */
    public static <T> List<T> rotate(final List<T> list, int distance) {
        if (list.isEmpty()) {
            return list;
        }

        int d = distance % list.size();
        if (d < 0) {
            d += list.size();
        }

        if (d == 0) {
            return list;
        }

        return new RotatedList<>(list, d);
    }

    private static class RotatedList<T> extends AbstractList<T> implements RandomAccess {

        private final List<T> in;
        private final int distance;

        RotatedList(List<T> list, int distance) {
            if (distance < 0 || distance >= list.size()) {
                throw new IllegalArgumentException();
            }
            if (!(list instanceof RandomAccess)) {
                throw new IllegalArgumentException();
            }
            this.in = list;
            this.distance = distance;
        }

        @Override
        public T get(int index) {
            int idx = distance + index;
            if (idx < 0 || idx >= in.size()) {
                idx -= in.size();
            }
            return in.get(idx);
        }

        @Override
        public int size() {
            return in.size();
        }
    }

    public static <T> List<T> reverse(List<T> list) {
        if (list instanceof Lists.ReverseList) {
            return ((Lists.ReverseList<T>) list).getForwardList();
        } else if (list instanceof RandomAccess) {
            return new Lists.RandomAccessReverseList<>(list);
        } else {
            return new Lists.ReverseList<>(list);
        }
    }

    /**
     * Based on https://github.com/google/guava/blob/master/guava/src/com/google/common/collect/Lists.java#L824
     */
    private static class ReverseList<T> extends AbstractList<T> {
        private final List<T> forwardList;

        ReverseList(List<T> forwardList) {
            this.forwardList = Objects.requireNonNull(forwardList);
        }

        List<T> getForwardList() {
            return forwardList;
        }

        private int reverseIndex(int index) {
            int size = size();
            Objects.checkIndex(index, size);
            return (size - 1) - index;
        }

        private int reversePosition(int index) {
            int size = size();
            Objects.checkIndex(index, size);
            return size - index;
        }

        @Override
        public void add(int index, @Nullable T element) {
            forwardList.add(reversePosition(index), element);
        }

        @Override
        public void clear() {
            forwardList.clear();
        }

        @Override
        public T remove(int index) {
            return forwardList.remove(reverseIndex(index));
        }

        @Override
        protected void removeRange(int fromIndex, int toIndex) {
            subList(fromIndex, toIndex).clear();
        }

        @Override
        public T set(int index, @Nullable T element) {
            return forwardList.set(reverseIndex(index), element);
        }

        @Override
        public T get(int index) {
            return forwardList.get(reverseIndex(index));
        }

        @Override
        public int size() {
            return forwardList.size();
        }

        @Override
        public List<T> subList(int fromIndex, int toIndex) {
            Objects.checkFromToIndex(fromIndex, toIndex, size());
            return reverse(forwardList.subList(reversePosition(toIndex), reversePosition(fromIndex)));
        }

        @Override
        public Iterator<T> iterator() {
            return listIterator();
        }

        @Override
        public ListIterator<T> listIterator(int index) {
            int start = reversePosition(index);
            final ListIterator<T> forwardIterator = forwardList.listIterator(start);
            return new ListIterator<T>() {

                boolean canRemoveOrSet;

                @Override
                public void add(T e) {
                    forwardIterator.add(e);
                    forwardIterator.previous();
                    canRemoveOrSet = false;
                }

                @Override
                public boolean hasNext() {
                    return forwardIterator.hasPrevious();
                }

                @Override
                public boolean hasPrevious() {
                    return forwardIterator.hasNext();
                }

                @Override
                public T next() {
                    if (!hasNext()) {
                        throw new NoSuchElementException();
                    }
                    canRemoveOrSet = true;
                    return forwardIterator.previous();
                }

                @Override
                public int nextIndex() {
                    return reversePosition(forwardIterator.nextIndex());
                }

                @Override
                public T previous() {
                    if (!hasPrevious()) {
                        throw new NoSuchElementException();
                    }
                    canRemoveOrSet = true;
                    return forwardIterator.next();
                }

                @Override
                public int previousIndex() {
                    return nextIndex() - 1;
                }

                @Override
                public void remove() {
                    assert (canRemoveOrSet);
                    forwardIterator.remove();
                    canRemoveOrSet = false;
                }

                @Override
                public void set(T e) {
                    assert (canRemoveOrSet);
                    forwardIterator.set(e);
                }
            };
        }
    }

    private static class RandomAccessReverseList<T> extends Lists.ReverseList<T> implements RandomAccess {
        RandomAccessReverseList(List<T> forwardList) {
            super(forwardList);
        }
    }

    public static <T> List<List<T>> partition(List<T> list, int size) {
        Objects.requireNonNull(list);
        Objects.checkIndex(0, size);
        return (list instanceof RandomAccess)
            ? new Lists.RandomAccessPartition<>(list, size)
            : new Lists.Partition<>(list, size);
    }

    private static class Partition<T> extends AbstractList<List<T>> {
        final List<T> list;
        final int size;

        Partition(List<T> list, int size) {
            this.list = list;
            this.size = size;
        }

        @Override
        public List<T> get(int index) {
            Objects.checkIndex(index, size());
            int start = index * size;
            int end = Math.min(start + size, list.size());
            return list.subList(start, end);
        }

        @Override
        public int size() {
            return (int) Math.ceil((double) list.size() / (double) size);
        }

        @Override
        public boolean isEmpty() {
            return list.isEmpty();
        }
    }

    private static class RandomAccessPartition<T> extends Lists.Partition<T> implements RandomAccess {
        RandomAccessPartition(List<T> list, int size) {
            super(list, size);
        }
    }
}
