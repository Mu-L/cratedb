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

package org.elasticsearch.threadpool;

import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ThreadFactory;

import org.elasticsearch.common.settings.Setting;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.unit.SizeValue;
import org.elasticsearch.common.util.concurrent.EsExecutors;
import org.elasticsearch.node.Node;

import io.crate.types.DataTypes;

/**
 * A builder for fixed executors.
 */
public class FixedExecutorBuilder extends ExecutorBuilder {

    protected final Setting<Integer> sizeSetting;
    protected final Setting<Integer> queueSizeSetting;

    /**
     * Construct a fixed executor builder.
     *
     * @param settings  the node-level settings
     * @param name      the name of the executor
     * @param size      the fixed number of threads
     * @param queueSize the size of the backing queue, -1 for unbounded
     */
    public FixedExecutorBuilder(Settings settings, String name, int size, int queueSize) {
        super(name);
        String prefix = ExecutorBuilder.PREFIX_PART + name;
        final String sizeKey = settingsKey(prefix, "size");
        this.sizeSetting = new Setting<>(
            sizeKey,
            _ -> Integer.toString(size),
            s -> Setting.parseInt(s, 1, applyHardSizeLimit(settings, name), sizeKey),
            DataTypes.INTEGER,
            Setting.Property.NodeScope
        );
        final String queueSizeKey = settingsKey(prefix, "queue_size");
        this.queueSizeSetting = Setting.intSetting(queueSizeKey, queueSize, Setting.Property.NodeScope);
    }

    @Override
    public List<Setting<?>> getRegisteredSettings() {
        return Arrays.asList(sizeSetting, queueSizeSetting);
    }

    @Override
    ThreadPool.ExecutorHolder build(final Settings settings) {
        final String nodeName = Node.NODE_NAME_SETTING.get(settings);
        final int size = sizeSetting.get(settings);
        final int queueSize = queueSizeSetting.get(settings);
        final ThreadFactory threadFactory = EsExecutors.daemonThreadFactory(EsExecutors.threadName(nodeName, name()));
        final ExecutorService executor = EsExecutors.newFixed(
            nodeName + "/" + name(),
            size,
            queueSize,
            threadFactory
        );
        final ThreadPool.Info info =
            new ThreadPool.Info(name(), ThreadPool.ThreadPoolType.FIXED, size, size, null, queueSize < 0 ? null : new SizeValue(queueSize));
        return new ThreadPool.ExecutorHolder(executor, info);
    }

    @Override
    String formatInfo(ThreadPool.Info info) {
        return String.format(
            Locale.ROOT,
            "name [%s], size [%d], queue size [%s]",
            info.name(),
            info.max(),
            info.queueSize() == null ? "unbounded" : info.queueSize());
    }

}
