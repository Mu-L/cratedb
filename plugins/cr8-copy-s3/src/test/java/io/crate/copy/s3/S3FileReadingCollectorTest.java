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

package io.crate.copy.s3;

import static io.crate.testing.TestingHelpers.createReference;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import io.crate.execution.dsl.projection.ColumnIndexWriterProjection;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.test.ESTestCase;
import org.elasticsearch.threadpool.TestThreadPool;
import org.elasticsearch.threadpool.ThreadPool;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3Client;
import com.amazonaws.services.s3.model.ObjectListing;
import com.amazonaws.services.s3.model.S3Object;
import com.amazonaws.services.s3.model.S3ObjectInputStream;
import com.amazonaws.services.s3.model.S3ObjectSummary;

import io.crate.analyze.CopyFromParserProperties;
import io.crate.copy.s3.common.S3ClientHelper;
import io.crate.data.BatchIterator;
import io.crate.data.Bucket;
import io.crate.data.Row;
import io.crate.data.RowConsumer;
import io.crate.data.testing.TestingRowConsumer;
import io.crate.execution.dsl.phases.FileUriCollectPhase;
import io.crate.execution.engine.collect.files.FileReadingIterator;
import io.crate.execution.engine.collect.files.LineCollectorExpression;
import io.crate.expression.InputFactory;
import io.crate.expression.reference.file.FileLineReferenceResolver;
import io.crate.metadata.CoordinatorTxnCtx;
import io.crate.metadata.Functions;
import io.crate.metadata.NodeContext;
import io.crate.metadata.Reference;
import io.crate.metadata.TransactionContext;
import io.crate.testing.TestingHelpers;
import io.crate.types.DataTypes;

public class S3FileReadingCollectorTest extends ESTestCase {
    private static ThreadPool THREAD_POOL;
    private InputFactory inputFactory;
    private final TransactionContext TXN_CTX = CoordinatorTxnCtx.systemTransactionContext();

    @BeforeClass
    public static void setUpClass() throws Exception {
        THREAD_POOL = new TestThreadPool(Thread.currentThread().getName());
    }

    @Before
    public void prepare() {
        NodeContext nodeCtx = new NodeContext(new Functions(Map.of()), null);
        inputFactory = new InputFactory(nodeCtx);
    }

    @AfterClass
    public static void tearDownClass() {
        ThreadPool.terminate(THREAD_POOL, 30, TimeUnit.SECONDS);
    }

    @Test
    public void testCollectFromS3Uri() throws Throwable {
        // this test just verifies the s3 schema detection and bucketName / prefix extraction from the uri.
        // real s3 interaction is mocked completely.
        TestingRowConsumer projector = getObjects("s3://fakebucket/foo");
        projector.getResult();
    }

    @Test
    public void testCollectWithOneSocketTimeout() throws Throwable {
        S3ObjectInputStream inputStream = mock(S3ObjectInputStream.class);

        byte[] fooLine = "{\"dummy\": \"foo\"}\n".getBytes(StandardCharsets.UTF_8);
        byte[] barLine = "{\"dummy\": \"bar\"}\n".getBytes(StandardCharsets.UTF_8);
        when(inputStream.read(any(byte[].class), anyInt(), anyInt()))
            .thenAnswer(new WriteBufferAnswer(fooLine))  // first line: foo
            .thenThrow(new SocketTimeoutException())  // exception causes retry
            .thenAnswer(new WriteBufferAnswer(fooLine))  // first line again, because of retry
            .thenAnswer(new WriteBufferAnswer(barLine))  // second line: bar
            .thenReturn(-1);

        TestingRowConsumer consumer = getObjects(Collections.singletonList("s3://fakebucket/foo"),
                                                 null,
                                                 inputStream);
        Bucket rows = consumer.getBucket();
        assertThat(rows).hasSize(2);
        assertThat(TestingHelpers.printedTable(rows)).isEqualTo("foo\nbar\n");
    }

    private TestingRowConsumer getObjects(String fileUri) throws Throwable {
        return getObjects(Collections.singletonList(fileUri), null);
    }

    private TestingRowConsumer getObjects(Collection<String> fileUris,
                                          String compression) throws Throwable {
        S3ObjectInputStream inputStream = mock(S3ObjectInputStream.class);
        when(inputStream.read(any(byte[].class), anyInt(), anyInt())).thenReturn(-1);
        return getObjects(fileUris, compression, inputStream);
    }

    private TestingRowConsumer getObjects(Collection<String> fileUris,
                                          String compression,
                                          S3ObjectInputStream s3InputStream) {
        TestingRowConsumer consumer = new TestingRowConsumer();
        getObjects(fileUris, compression, s3InputStream, consumer);
        return consumer;
    }

    private void getObjects(Collection<String> fileUris,
                            String compression,
                            final S3ObjectInputStream s3InputStream,
                            RowConsumer consumer) {
        BatchIterator<Row> iterator = createBatchIterator(fileUris,
                                                          compression,
                                                          s3InputStream);
        consumer.accept(iterator, null);
    }

    private BatchIterator<Row> createBatchIterator(Collection<String> fileUris,
                                                   String compression,
                                                   final S3ObjectInputStream s3InputStream) {
        InputFactory.Context<LineCollectorExpression<?>> ctx =
            inputFactory.ctxForRefs(TXN_CTX, FileLineReferenceResolver::getImplementation);
        Reference dummy = createReference("dummy", DataTypes.STRING);
        List<Reference> targetColumns = new ArrayList<>();
        targetColumns.add(dummy);

        ctx.add(targetColumns);
        //noinspection unchecked
        ColumnIndexWriterProjection projection = mock(ColumnIndexWriterProjection.class);
        when(projection.allTargetColumns()).thenReturn(targetColumns);

        return FileReadingIterator.newInstance(
            fileUris,
            ctx,
            compression,
            Map.of(
                S3FileInputFactory.NAME,
                (uri, withClauseOptions) -> new S3FileInput(new S3ClientHelper() {
                    @Override
                    protected AmazonS3 initClient(String accessKey, String secretKey, String endpoint, String protocol) {
                        AmazonS3 client = mock(AmazonS3Client.class);
                        ObjectListing objectListing = mock(ObjectListing.class);
                        S3ObjectSummary summary = mock(S3ObjectSummary.class);
                        S3Object s3Object = mock(S3Object.class);
                        when(client.listObjects(anyString(), anyString())).thenReturn(objectListing);
                        when(objectListing.getObjectSummaries()).thenReturn(Collections.singletonList(summary));
                        when(summary.getKey()).thenReturn("foo");
                        when(client.getObject("fakebucket", "foo")).thenReturn(s3Object);
                        when(s3Object.getObjectContent()).thenReturn(s3InputStream);
                        when(client.listNextBatchOfObjects(any(ObjectListing.class))).thenReturn(objectListing);
                        when(objectListing.isTruncated()).thenReturn(false);
                        return client;
                    }
                }, uri, "https")),
            false,
            1,
            0,
            List.of("dummy"),
            CopyFromParserProperties.DEFAULT,
            FileUriCollectPhase.InputFormat.JSON,
            Settings.EMPTY,
            projection,
            THREAD_POOL.scheduler());
    }

    private record WriteBufferAnswer(byte[] bytes) implements Answer<Integer> {

        @Override
        public Integer answer(InvocationOnMock invocation) {
            byte[] buffer = (byte[]) invocation.getArguments()[0];
            System.arraycopy(bytes, 0, buffer, 0, bytes.length);
            return bytes.length;
        }
    }
}
