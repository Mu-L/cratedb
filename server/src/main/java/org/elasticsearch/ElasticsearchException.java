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

package org.elasticsearch;

import static java.util.Collections.unmodifiableMap;
import static org.elasticsearch.cluster.metadata.IndexMetadata.INDEX_UUID_NA_VALUE;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.elasticsearch.action.admin.indices.alias.AliasesNotFoundException;
import org.elasticsearch.action.support.replication.ReplicationOperation;
import org.elasticsearch.cluster.action.shard.ShardStateAction;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.io.stream.Writeable;
import org.elasticsearch.common.logging.LoggerMessageFormat;
import org.elasticsearch.index.Index;
import org.elasticsearch.index.shard.PrimaryShardClosedException;
import org.elasticsearch.index.shard.ShardId;
import org.elasticsearch.rest.RestStatus;
import org.elasticsearch.transport.TcpTransport;

import io.crate.common.CheckedFunction;
import io.crate.exceptions.ArrayViaDocValuesUnsupportedException;
import io.crate.exceptions.RoleUnknownException;
import io.crate.exceptions.SQLExceptions;
import io.crate.fdw.ServerAlreadyExistsException;
import io.crate.fdw.UserMappingAlreadyExists;
import io.crate.protocols.postgres.PGErrorStatus;
import io.crate.rest.action.HttpErrorStatus;

/**
 * A base class for all elasticsearch exceptions.
 */
public class ElasticsearchException extends RuntimeException implements Writeable {

    private static final Version UNKNOWN_VERSION_ADDED = Version.fromId(0);

    private static final String INDEX_METADATA_KEY = "es.index";
    private static final String INDEX_METADATA_KEY_UUID = "es.index_uuid";
    private static final String SHARD_METADATA_KEY = "es.shard";
    private static final String RESOURCE_METADATA_TYPE_KEY = "es.resource.type";
    private static final String RESOURCE_METADATA_ID_KEY = "es.resource.id";

    private static final Map<Integer, CheckedFunction<StreamInput, ? extends ElasticsearchException, IOException>> ID_TO_SUPPLIER;
    private static final Map<Class<? extends ElasticsearchException>, ElasticsearchExceptionHandle> CLASS_TO_ELASTICSEARCH_EXCEPTION_HANDLE;
    private final Map<String, List<String>> metadata = new HashMap<>();
    private final Map<String, List<String>> headers = new HashMap<>();

    /**
     * Construct a <code>ElasticsearchException</code> with the specified cause exception.
     */
    public ElasticsearchException(Throwable cause) {
        super(cause);
    }

    /**
     * Construct a <code>ElasticsearchException</code> with the specified detail message.
     *
     * The message can be parameterized using <code>{}</code> as placeholders for the given
     * arguments
     *
     * @param msg  the detail message
     * @param args the arguments for the message
     */
    public ElasticsearchException(String msg, Object... args) {
        super(LoggerMessageFormat.format(msg, args));
    }

    /**
     * Construct a <code>ElasticsearchException</code> with the specified detail message
     * and nested exception.
     *
     * The message can be parameterized using <code>{}</code> as placeholders for the given
     * arguments
     *
     * @param msg   the detail message
     * @param cause the nested exception
     * @param args  the arguments for the message
     */
    public ElasticsearchException(String msg, Throwable cause, Object... args) {
        super(LoggerMessageFormat.format(msg, args), cause);
    }

    public ElasticsearchException(StreamInput in) throws IOException {
        super(in.readOptionalString(), in.readException());
        readStackTrace(this, in);
        headers.putAll(in.readMapOfLists(StreamInput::readString, StreamInput::readString));
        metadata.putAll(in.readMapOfLists(StreamInput::readString, StreamInput::readString));
    }

    /**
     * Adds a new piece of metadata with the given key.
     * If the provided key is already present, the corresponding metadata will be replaced
     */
    public void addMetadata(String key, String... values) {
        addMetadata(key, Arrays.asList(values));
    }

    /**
     * Adds a new piece of metadata with the given key.
     * If the provided key is already present, the corresponding metadata will be replaced
     */
    public void addMetadata(String key, List<String> values) {
        //we need to enforce this otherwise bw comp doesn't work properly, as "es." was the previous criteria to split headers in two sets
        if (key.startsWith("es.") == false) {
            throw new IllegalArgumentException("exception metadata must start with [es.], found [" + key + "] instead");
        }
        this.metadata.put(key, values);
    }

    public PGErrorStatus pgErrorStatus() {
        return PGErrorStatus.INTERNAL_ERROR;
    }

    public HttpErrorStatus httpErrorStatus() {
        return HttpErrorStatus.UNHANDLED_SERVER_ERROR;
    }

    /**
     * Returns a set of all metadata keys on this exception
     */
    public Set<String> getMetadataKeys() {
        return metadata.keySet();
    }

    /**
     * Returns the list of metadata values for the given key or {@code null} if no metadata for the
     * given key exists.
     */
    public List<String> getMetadata(String key) {
        return metadata.get(key);
    }

    protected Map<String, List<String>> getMetadata() {
        return metadata;
    }

    /**
     * Adds a new header with the given key.
     * This method will replace existing header if a header with the same key already exists
     */
    public void addHeader(String key, List<String> value) {
        //we need to enforce this otherwise bw comp doesn't work properly, as "es." was the previous criteria to split headers in two sets
        if (key.startsWith("es.")) {
            throw new IllegalArgumentException("exception headers must not start with [es.], found [" + key + "] instead");
        }
        this.headers.put(key, value);
    }

    /**
     * Returns a set of all header keys on this exception
     */
    public Set<String> getHeaderKeys() {
        return headers.keySet();
    }

    /**
     * Returns the list of header values for the given key or {@code null} if no header for the
     * given key exists.
     */
    public List<String> getHeader(String key) {
        return headers.get(key);
    }

    protected Map<String, List<String>> getHeaders() {
        return headers;
    }

    /**
     * Returns the rest status code associated with this exception.
     */
    public RestStatus status() {
        Throwable cause = unwrapCause();
        if (cause == this) {
            return RestStatus.INTERNAL_SERVER_ERROR;
        } else {
            return SQLExceptions.status(cause);
        }
    }

    /**
     * Unwraps the actual cause from the exception for cases when the exception is a
     * {@link ElasticsearchWrapperException}.
     *
     * @see ExceptionsHelper#unwrapCause(Throwable)
     */
    public Throwable unwrapCause() {
        return SQLExceptions.unwrap(this);
    }

    /**
     * Return the detail message, including the message from the nested exception
     * if there is one.
     */
    public String getDetailedMessage() {
        if (getCause() != null) {
            StringBuilder sb = new StringBuilder();
            sb.append(toString()).append("; ");
            if (getCause() instanceof ElasticsearchException) {
                sb.append(((ElasticsearchException) getCause()).getDetailedMessage());
            } else {
                sb.append(getCause());
            }
            return sb.toString();
        } else {
            return super.toString();
        }
    }

    /**
     * Retrieve the innermost cause of this exception, if none, returns the current exception.
     */
    public Throwable getRootCause() {
        Throwable rootCause = this;
        Throwable cause = getCause();
        while (cause != null && cause != rootCause) {
            rootCause = cause;
            cause = cause.getCause();
        }
        return rootCause;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeOptionalString(this.getMessage());
        out.writeException(this.getCause());
        writeStackTraces(this, out, StreamOutput::writeException);
        out.writeMapOfLists(headers, StreamOutput::writeString, StreamOutput::writeString);
        out.writeMapOfLists(metadata, StreamOutput::writeString, StreamOutput::writeString);
    }

    public static ElasticsearchException readException(StreamInput input, int id) throws IOException {
        CheckedFunction<StreamInput, ? extends ElasticsearchException, IOException> elasticsearchException = ID_TO_SUPPLIER.get(id);
        if (elasticsearchException == null) {
            throw new IllegalStateException("unknown exception for id: " + id);
        }
        return elasticsearchException.apply(input);
    }

    /**
     * Returns <code>true</code> iff the given class is a registered for an exception to be read.
     */
    public static boolean isRegistered(Class<? extends Throwable> exception, Version version) {
        ElasticsearchExceptionHandle elasticsearchExceptionHandle = CLASS_TO_ELASTICSEARCH_EXCEPTION_HANDLE.get(exception);
        if (elasticsearchExceptionHandle != null) {
            return version.onOrAfter(elasticsearchExceptionHandle.versionAdded);
        }
        return false;
    }

    /**
     * Returns the serialization id the given exception.
     */
    public static int getId(Class<? extends ElasticsearchException> exception) {
        return CLASS_TO_ELASTICSEARCH_EXCEPTION_HANDLE.get(exception).id;
    }

    protected String getExceptionName() {
        return getExceptionName(this);
    }

    /**
     * Returns a name for the given exception. This method strips {@code Elasticsearch} prefixes from exception names.
     */
    public static String getExceptionName(Throwable ex) {
        String simpleName = ex.getClass().getSimpleName();
        if (simpleName.startsWith("Elasticsearch")) {
            simpleName = simpleName.substring("Elasticsearch".length());
        }
        return simpleName;
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        if (metadata.containsKey(INDEX_METADATA_KEY)) {
            builder.append(getIndex());
            if (metadata.containsKey(SHARD_METADATA_KEY)) {
                builder.append('[').append(getShardId()).append(']');
            }
            builder.append(' ');
        }
        return builder.append(super.toString().trim()).toString();
    }

    /**
     * Deserializes stacktrace elements as well as suppressed exceptions from the given output stream and
     * adds it to the given exception.
     */
    public static <T extends Throwable> T readStackTrace(T throwable, StreamInput in) throws IOException {
        throwable.setStackTrace(in.readArray(i -> {
            final String declaringClasss = i.readString();
            final String fileName = i.readOptionalString();
            final String methodName = i.readString();
            final int lineNumber = i.readVInt();
            return new StackTraceElement(declaringClasss, methodName, fileName, lineNumber);
        }, StackTraceElement[]::new));

        int numSuppressed = in.readVInt();
        for (int i = 0; i < numSuppressed; i++) {
            throwable.addSuppressed(in.readException());
        }
        return throwable;
    }

    /**
     * Serializes the given exceptions stacktrace elements as well as it's suppressed exceptions to the given output stream.
     */
    public static <T extends Throwable> T writeStackTraces(T throwable, StreamOutput out,
                                                           Writer<Throwable> exceptionWriter) throws IOException {
        out.writeArray((o, v) -> {
            o.writeString(v.getClassName());
            o.writeOptionalString(v.getFileName());
            o.writeString(v.getMethodName());
            o.writeVInt(v.getLineNumber());
        }, throwable.getStackTrace());
        out.writeArray(exceptionWriter, throwable.getSuppressed());
        return throwable;
    }

    /**
     * This is the list of Exceptions Elasticsearch can throw over the wire or save into a corruption marker. Each value in the enum is a
     * single exception tying the Class to an id for use of the encode side and the id back to a constructor for use on the decode side. As
     * such its ok if the exceptions to change names so long as their constructor can still read the exception. Each exception is listed
     * in id order below. If you want to remove an exception leave a tombstone comment and mark the id as null in
     * ExceptionSerializationTests.testIds.ids.
     */
    private enum ElasticsearchExceptionHandle {
        INDEX_SHARD_SNAPSHOT_FAILED_EXCEPTION(org.elasticsearch.index.snapshots.IndexShardSnapshotFailedException.class,
                org.elasticsearch.index.snapshots.IndexShardSnapshotFailedException::new, 0, UNKNOWN_VERSION_ADDED),
        // 1 was DfsPhaseExecutionException
        EXECUTION_CANCELLED_EXCEPTION(org.elasticsearch.common.util.CancellableThreads.ExecutionCancelledException.class,
                org.elasticsearch.common.util.CancellableThreads.ExecutionCancelledException::new, 2, UNKNOWN_VERSION_ADDED),
        MASTER_NOT_DISCOVERED_EXCEPTION(org.elasticsearch.discovery.MasterNotDiscoveredException.class,
                org.elasticsearch.discovery.MasterNotDiscoveredException::new, 3, UNKNOWN_VERSION_ADDED),
        ELASTICSEARCH_SECURITY_EXCEPTION(org.elasticsearch.ElasticsearchSecurityException.class,
                org.elasticsearch.ElasticsearchSecurityException::new, 4, UNKNOWN_VERSION_ADDED),
        INDEX_SHARD_RESTORE_EXCEPTION(org.elasticsearch.index.snapshots.IndexShardRestoreException.class,
                org.elasticsearch.index.snapshots.IndexShardRestoreException::new, 5, UNKNOWN_VERSION_ADDED),
        INDEX_CLOSED_EXCEPTION(org.elasticsearch.indices.IndexClosedException.class,
                org.elasticsearch.indices.IndexClosedException::new, 6, UNKNOWN_VERSION_ADDED),
        BIND_HTTP_EXCEPTION(org.elasticsearch.http.BindHttpException.class,
                org.elasticsearch.http.BindHttpException::new, 7, UNKNOWN_VERSION_ADDED),
        // 8 was ReduceSearchPhaseException
        NODE_CLOSED_EXCEPTION(org.elasticsearch.node.NodeClosedException.class,
                org.elasticsearch.node.NodeClosedException::new, 9, UNKNOWN_VERSION_ADDED),
        SNAPSHOT_FAILED_ENGINE_EXCEPTION(org.elasticsearch.index.engine.SnapshotFailedEngineException.class,
                org.elasticsearch.index.engine.SnapshotFailedEngineException::new, 10, UNKNOWN_VERSION_ADDED),
        SHARD_NOT_FOUND_EXCEPTION(org.elasticsearch.index.shard.ShardNotFoundException.class,
                org.elasticsearch.index.shard.ShardNotFoundException::new, 11, UNKNOWN_VERSION_ADDED),
        CONNECT_TRANSPORT_EXCEPTION(org.elasticsearch.transport.ConnectTransportException.class,
                org.elasticsearch.transport.ConnectTransportException::new, 12, UNKNOWN_VERSION_ADDED),
        NOT_SERIALIZABLE_TRANSPORT_EXCEPTION(org.elasticsearch.transport.NotSerializableTransportException.class,
                org.elasticsearch.transport.NotSerializableTransportException::new, 13, UNKNOWN_VERSION_ADDED),
        RESPONSE_HANDLER_FAILURE_TRANSPORT_EXCEPTION(org.elasticsearch.transport.ResponseHandlerFailureTransportException.class,
                org.elasticsearch.transport.ResponseHandlerFailureTransportException::new, 14, UNKNOWN_VERSION_ADDED),
        INDEX_CREATION_EXCEPTION(org.elasticsearch.indices.IndexCreationException.class,
                org.elasticsearch.indices.IndexCreationException::new, 15, UNKNOWN_VERSION_ADDED),
        INDEX_NOT_FOUND_EXCEPTION(org.elasticsearch.index.IndexNotFoundException.class,
                org.elasticsearch.index.IndexNotFoundException::new, 16, UNKNOWN_VERSION_ADDED),
        ILLEGAL_SHARD_ROUTING_STATE_EXCEPTION(org.elasticsearch.cluster.routing.IllegalShardRoutingStateException.class,
                org.elasticsearch.cluster.routing.IllegalShardRoutingStateException::new, 17, UNKNOWN_VERSION_ADDED),
        BROADCAST_SHARD_OPERATION_FAILED_EXCEPTION(org.elasticsearch.action.support.broadcast.BroadcastShardOperationFailedException.class,
                org.elasticsearch.action.support.broadcast.BroadcastShardOperationFailedException::new, 18, UNKNOWN_VERSION_ADDED),
        RESOURCE_NOT_FOUND_EXCEPTION(org.elasticsearch.ResourceNotFoundException.class,
                org.elasticsearch.ResourceNotFoundException::new, 19, UNKNOWN_VERSION_ADDED),
        ACTION_TRANSPORT_EXCEPTION(org.elasticsearch.transport.ActionTransportException.class,
                org.elasticsearch.transport.ActionTransportException::new, 20, UNKNOWN_VERSION_ADDED),
        ELASTICSEARCH_GENERATION_EXCEPTION(org.elasticsearch.ElasticsearchGenerationException.class,
                org.elasticsearch.ElasticsearchGenerationException::new, 21, UNKNOWN_VERSION_ADDED),
        //      22 was CreateFailedEngineException
        INDEX_SHARD_STARTED_EXCEPTION(org.elasticsearch.index.shard.IndexShardStartedException.class,
                org.elasticsearch.index.shard.IndexShardStartedException::new, 23, UNKNOWN_VERSION_ADDED),
        // 24 was SearchContextMissingException
        // 25 was GeneralScriptException
        // 26 was BatchOperationException
        // 27 was SnapshotCreationException
        // 28 was DeleteFailedEngineException, deprecated in 6.0, removed in 7.0
        DOCUMENT_MISSING_EXCEPTION(org.elasticsearch.index.engine.DocumentMissingException.class,
                org.elasticsearch.index.engine.DocumentMissingException::new, 29, UNKNOWN_VERSION_ADDED),
        SNAPSHOT_EXCEPTION(org.elasticsearch.snapshots.SnapshotException.class,
                org.elasticsearch.snapshots.SnapshotException::new, 30, UNKNOWN_VERSION_ADDED),
        INVALID_ALIAS_NAME_EXCEPTION(org.elasticsearch.indices.InvalidAliasNameException.class,
                org.elasticsearch.indices.InvalidAliasNameException::new, 31, UNKNOWN_VERSION_ADDED),
        INVALID_INDEX_NAME_EXCEPTION(org.elasticsearch.indices.InvalidIndexNameException.class,
                org.elasticsearch.indices.InvalidIndexNameException::new, 32, UNKNOWN_VERSION_ADDED),
        INDEX_PRIMARY_SHARD_NOT_ALLOCATED_EXCEPTION(org.elasticsearch.indices.IndexPrimaryShardNotAllocatedException.class,
                org.elasticsearch.indices.IndexPrimaryShardNotAllocatedException::new, 33, UNKNOWN_VERSION_ADDED),
        TRANSPORT_EXCEPTION(org.elasticsearch.transport.TransportException.class,
                org.elasticsearch.transport.TransportException::new, 34, UNKNOWN_VERSION_ADDED),
        ELASTICSEARCH_PARSE_EXCEPTION(org.elasticsearch.ElasticsearchParseException.class,
                org.elasticsearch.ElasticsearchParseException::new, 35, UNKNOWN_VERSION_ADDED),
        // 36 was SearchException
        MAPPER_EXCEPTION(org.elasticsearch.index.mapper.MapperException.class,
                org.elasticsearch.index.mapper.MapperException::new, 37, UNKNOWN_VERSION_ADDED),
        INVALID_TYPE_NAME_EXCEPTION(org.elasticsearch.indices.InvalidTypeNameException.class,
                org.elasticsearch.indices.InvalidTypeNameException::new, 38, UNKNOWN_VERSION_ADDED),
        SNAPSHOT_RESTORE_EXCEPTION(org.elasticsearch.snapshots.SnapshotRestoreException.class,
                org.elasticsearch.snapshots.SnapshotRestoreException::new, 39, UNKNOWN_VERSION_ADDED),
        PARSING_EXCEPTION(org.elasticsearch.common.ParsingException.class, org.elasticsearch.common.ParsingException::new, 40,
            UNKNOWN_VERSION_ADDED),
        INDEX_SHARD_CLOSED_EXCEPTION(org.elasticsearch.index.shard.IndexShardClosedException.class,
                org.elasticsearch.index.shard.IndexShardClosedException::new, 41, UNKNOWN_VERSION_ADDED),
        RECOVER_FILES_RECOVERY_EXCEPTION(org.elasticsearch.indices.recovery.RecoverFilesRecoveryException.class,
                org.elasticsearch.indices.recovery.RecoverFilesRecoveryException::new, 42, UNKNOWN_VERSION_ADDED),
        TRUNCATED_TRANSLOG_EXCEPTION(org.elasticsearch.index.translog.TruncatedTranslogException.class,
                org.elasticsearch.index.translog.TruncatedTranslogException::new, 43, UNKNOWN_VERSION_ADDED),
        RECOVERY_FAILED_EXCEPTION(org.elasticsearch.indices.recovery.RecoveryFailedException.class,
                org.elasticsearch.indices.recovery.RecoveryFailedException::new, 44, UNKNOWN_VERSION_ADDED),
        INDEX_SHARD_RELOCATED_EXCEPTION(org.elasticsearch.index.shard.IndexShardRelocatedException.class,
                org.elasticsearch.index.shard.IndexShardRelocatedException::new, 45, UNKNOWN_VERSION_ADDED),
        NODE_SHOULD_NOT_CONNECT_EXCEPTION(org.elasticsearch.transport.NodeShouldNotConnectException.class,
                org.elasticsearch.transport.NodeShouldNotConnectException::new, 46, UNKNOWN_VERSION_ADDED),
        // 47 used to be for IndexTemplateAlreadyExistsException which was deprecated in 5.1 removed in 6.0
        TRANSLOG_CORRUPTED_EXCEPTION(org.elasticsearch.index.translog.TranslogCorruptedException.class,
                org.elasticsearch.index.translog.TranslogCorruptedException::new, 48, UNKNOWN_VERSION_ADDED),
        CLUSTER_BLOCK_EXCEPTION(org.elasticsearch.cluster.block.ClusterBlockException.class,
                org.elasticsearch.cluster.block.ClusterBlockException::new, 49, UNKNOWN_VERSION_ADDED),
        // 50 was FetchPhaseExecutionException
        // 51 used to be for IndexShardAlreadyExistsException which was deprecated in 5.1 removed in 6.0
        VERSION_CONFLICT_ENGINE_EXCEPTION(org.elasticsearch.index.engine.VersionConflictEngineException.class,
                org.elasticsearch.index.engine.VersionConflictEngineException::new, 52, UNKNOWN_VERSION_ADDED),
        ENGINE_EXCEPTION(org.elasticsearch.index.engine.EngineException.class, org.elasticsearch.index.engine.EngineException::new, 53,
            UNKNOWN_VERSION_ADDED),
        // 54 was DocumentAlreadyExistsException, which is superseded by VersionConflictEngineException
        NO_SUCH_NODE_EXCEPTION(org.elasticsearch.action.NoSuchNodeException.class, org.elasticsearch.action.NoSuchNodeException::new, 55,
            UNKNOWN_VERSION_ADDED),
        SETTINGS_EXCEPTION(org.elasticsearch.common.settings.SettingsException.class,
                org.elasticsearch.common.settings.SettingsException::new, 56, UNKNOWN_VERSION_ADDED),
        INDEX_TEMPLATE_MISSING_EXCEPTION(org.elasticsearch.indices.IndexTemplateMissingException.class,
                org.elasticsearch.indices.IndexTemplateMissingException::new, 57, UNKNOWN_VERSION_ADDED),
        SEND_REQUEST_TRANSPORT_EXCEPTION(org.elasticsearch.transport.SendRequestTransportException.class,
                org.elasticsearch.transport.SendRequestTransportException::new, 58, UNKNOWN_VERSION_ADDED),
        // 59 used to be EsRejectedExecutionException
        // 60 used to be for EarlyTerminationException
        // 61 used to be for RoutingValidationException
        NOT_SERIALIZABLE_EXCEPTION_WRAPPER(org.elasticsearch.common.io.stream.NotSerializableExceptionWrapper.class,
                org.elasticsearch.common.io.stream.NotSerializableExceptionWrapper::new, 62, UNKNOWN_VERSION_ADDED),
        // 63 was AliasFilterParsingException
        // 64 was DeleteByQueryFailedEngineException, which was removed in 5.0
        GATEWAY_EXCEPTION(org.elasticsearch.gateway.GatewayException.class, org.elasticsearch.gateway.GatewayException::new, 65,
            UNKNOWN_VERSION_ADDED),
        INDEX_SHARD_NOT_RECOVERING_EXCEPTION(org.elasticsearch.index.shard.IndexShardNotRecoveringException.class,
                org.elasticsearch.index.shard.IndexShardNotRecoveringException::new, 66, UNKNOWN_VERSION_ADDED),
        HTTP_EXCEPTION(org.elasticsearch.http.HttpException.class, org.elasticsearch.http.HttpException::new, 67, UNKNOWN_VERSION_ADDED),
        ELASTICSEARCH_EXCEPTION(org.elasticsearch.ElasticsearchException.class,
                org.elasticsearch.ElasticsearchException::new, 68, UNKNOWN_VERSION_ADDED),
        SNAPSHOT_MISSING_EXCEPTION(org.elasticsearch.snapshots.SnapshotMissingException.class,
                org.elasticsearch.snapshots.SnapshotMissingException::new, 69, UNKNOWN_VERSION_ADDED),
        PRIMARY_MISSING_ACTION_EXCEPTION(org.elasticsearch.action.PrimaryMissingActionException.class,
                org.elasticsearch.action.PrimaryMissingActionException::new, 70, UNKNOWN_VERSION_ADDED),
        FAILED_NODE_EXCEPTION(org.elasticsearch.action.FailedNodeException.class, org.elasticsearch.action.FailedNodeException::new, 71,
            UNKNOWN_VERSION_ADDED),
        // 72 was SearchParseException
        CONCURRENT_SNAPSHOT_EXECUTION_EXCEPTION(org.elasticsearch.snapshots.ConcurrentSnapshotExecutionException.class,
                org.elasticsearch.snapshots.ConcurrentSnapshotExecutionException::new, 73, UNKNOWN_VERSION_ADDED),
        BLOB_STORE_EXCEPTION(org.elasticsearch.common.blobstore.BlobStoreException.class,
                org.elasticsearch.common.blobstore.BlobStoreException::new, 74, UNKNOWN_VERSION_ADDED),
        INCOMPATIBLE_CLUSTER_STATE_VERSION_EXCEPTION(org.elasticsearch.cluster.IncompatibleClusterStateVersionException.class,
                org.elasticsearch.cluster.IncompatibleClusterStateVersionException::new, 75, UNKNOWN_VERSION_ADDED),
        RECOVERY_ENGINE_EXCEPTION(org.elasticsearch.index.engine.RecoveryEngineException.class,
                org.elasticsearch.index.engine.RecoveryEngineException::new, 76, UNKNOWN_VERSION_ADDED),
        UNCATEGORIZED_EXECUTION_EXCEPTION(org.elasticsearch.common.util.concurrent.UncategorizedExecutionException.class,
                org.elasticsearch.common.util.concurrent.UncategorizedExecutionException::new, 77, UNKNOWN_VERSION_ADDED),
        // 78 was TimestampParsingException
        // 79 was RoutingMissingException
        // 80 was IndexFailedEngineException, deprecated in 6.0, removed in 7.0
        INDEX_SHARD_RESTORE_FAILED_EXCEPTION(org.elasticsearch.index.snapshots.IndexShardRestoreFailedException.class,
                org.elasticsearch.index.snapshots.IndexShardRestoreFailedException::new, 81, UNKNOWN_VERSION_ADDED),
        REPOSITORY_EXCEPTION(org.elasticsearch.repositories.RepositoryException.class,
                org.elasticsearch.repositories.RepositoryException::new, 82, UNKNOWN_VERSION_ADDED),
        RECEIVE_TIMEOUT_TRANSPORT_EXCEPTION(org.elasticsearch.transport.ReceiveTimeoutTransportException.class,
                org.elasticsearch.transport.ReceiveTimeoutTransportException::new, 83, UNKNOWN_VERSION_ADDED),
        NODE_DISCONNECTED_EXCEPTION(org.elasticsearch.transport.NodeDisconnectedException.class,
                org.elasticsearch.transport.NodeDisconnectedException::new, 84, UNKNOWN_VERSION_ADDED),
        // 85 used to be for AlreadyExpiredException
        // 86 used to be for AggregationExecutionException
        // 87 used to be for MergeMappingException
        INVALID_INDEX_TEMPLATE_EXCEPTION(org.elasticsearch.indices.InvalidIndexTemplateException.class,
                org.elasticsearch.indices.InvalidIndexTemplateException::new, 88, UNKNOWN_VERSION_ADDED),
        REFRESH_FAILED_ENGINE_EXCEPTION(org.elasticsearch.index.engine.RefreshFailedEngineException.class,
                org.elasticsearch.index.engine.RefreshFailedEngineException::new, 90, UNKNOWN_VERSION_ADDED),
        // 91 used to be for AggregationInitializationException
        DELAY_RECOVERY_EXCEPTION(org.elasticsearch.indices.recovery.DelayRecoveryException.class,
                org.elasticsearch.indices.recovery.DelayRecoveryException::new, 92, UNKNOWN_VERSION_ADDED),
        // 93 used to be for IndexWarmerMissingException
        NO_NODE_AVAILABLE_EXCEPTION(org.elasticsearch.client.transport.NoNodeAvailableException.class,
                org.elasticsearch.client.transport.NoNodeAvailableException::new, 94, UNKNOWN_VERSION_ADDED),
        INVALID_SNAPSHOT_NAME_EXCEPTION(org.elasticsearch.snapshots.InvalidSnapshotNameException.class,
                org.elasticsearch.snapshots.InvalidSnapshotNameException::new, 96, UNKNOWN_VERSION_ADDED),
        ILLEGAL_INDEX_SHARD_STATE_EXCEPTION(org.elasticsearch.index.shard.IllegalIndexShardStateException.class,
                org.elasticsearch.index.shard.IllegalIndexShardStateException::new, 97, UNKNOWN_VERSION_ADDED),
        INDEX_SHARD_SNAPSHOT_EXCEPTION(org.elasticsearch.index.snapshots.IndexShardSnapshotException.class,
                org.elasticsearch.index.snapshots.IndexShardSnapshotException::new, 98, UNKNOWN_VERSION_ADDED),
        INDEX_SHARD_NOT_STARTED_EXCEPTION(org.elasticsearch.index.shard.IndexShardNotStartedException.class,
                org.elasticsearch.index.shard.IndexShardNotStartedException::new, 99, UNKNOWN_VERSION_ADDED),
        // 100 used to bew for SearchPhaseExecutionException
        ACTION_NOT_FOUND_TRANSPORT_EXCEPTION(org.elasticsearch.transport.ActionNotFoundTransportException.class,
                org.elasticsearch.transport.ActionNotFoundTransportException::new, 101, UNKNOWN_VERSION_ADDED),
        TRANSPORT_SERIALIZATION_EXCEPTION(org.elasticsearch.transport.TransportSerializationException.class,
                org.elasticsearch.transport.TransportSerializationException::new, 102, UNKNOWN_VERSION_ADDED),
        REMOTE_TRANSPORT_EXCEPTION(org.elasticsearch.transport.RemoteTransportException.class,
                org.elasticsearch.transport.RemoteTransportException::new, 103, UNKNOWN_VERSION_ADDED),
        ENGINE_CREATION_FAILURE_EXCEPTION(org.elasticsearch.index.engine.EngineCreationFailureException.class,
                org.elasticsearch.index.engine.EngineCreationFailureException::new, 104, UNKNOWN_VERSION_ADDED),
        ROUTING_EXCEPTION(org.elasticsearch.cluster.routing.RoutingException.class,
                org.elasticsearch.cluster.routing.RoutingException::new, 105, UNKNOWN_VERSION_ADDED),
        INDEX_SHARD_RECOVERY_EXCEPTION(org.elasticsearch.index.shard.IndexShardRecoveryException.class,
                org.elasticsearch.index.shard.IndexShardRecoveryException::new, 106, UNKNOWN_VERSION_ADDED),
        REPOSITORY_MISSING_EXCEPTION(org.elasticsearch.repositories.RepositoryMissingException.class,
                org.elasticsearch.repositories.RepositoryMissingException::new, 107, UNKNOWN_VERSION_ADDED),
        DOCUMENT_SOURCE_MISSING_EXCEPTION(org.elasticsearch.index.engine.DocumentSourceMissingException.class,
                org.elasticsearch.index.engine.DocumentSourceMissingException::new, 109, UNKNOWN_VERSION_ADDED),
        // 110 used to be FlushNotAllowedEngineException
        NO_CLASS_SETTINGS_EXCEPTION(org.elasticsearch.common.settings.NoClassSettingsException.class,
                org.elasticsearch.common.settings.NoClassSettingsException::new, 111, UNKNOWN_VERSION_ADDED),
        BIND_TRANSPORT_EXCEPTION(org.elasticsearch.transport.BindTransportException.class,
                org.elasticsearch.transport.BindTransportException::new, 112, UNKNOWN_VERSION_ADDED),
        ALIASES_NOT_FOUND_EXCEPTION(AliasesNotFoundException.class,
                AliasesNotFoundException::new, 113, UNKNOWN_VERSION_ADDED),
        INDEX_SHARD_RECOVERING_EXCEPTION(org.elasticsearch.index.shard.IndexShardRecoveringException.class,
                org.elasticsearch.index.shard.IndexShardRecoveringException::new, 114, UNKNOWN_VERSION_ADDED),
        TRANSLOG_EXCEPTION(org.elasticsearch.index.translog.TranslogException.class,
                org.elasticsearch.index.translog.TranslogException::new, 115, UNKNOWN_VERSION_ADDED),
        PROCESS_CLUSTER_EVENT_TIMEOUT_EXCEPTION(org.elasticsearch.cluster.metadata.ProcessClusterEventTimeoutException.class,
                org.elasticsearch.cluster.metadata.ProcessClusterEventTimeoutException::new, 116, UNKNOWN_VERSION_ADDED),
        RETRY_ON_PRIMARY_EXCEPTION(ReplicationOperation.RetryOnPrimaryException.class,
                ReplicationOperation.RetryOnPrimaryException::new, 117, UNKNOWN_VERSION_ADDED),
        ELASTICSEARCH_TIMEOUT_EXCEPTION(org.elasticsearch.ElasticsearchTimeoutException.class,
                org.elasticsearch.ElasticsearchTimeoutException::new, 118, UNKNOWN_VERSION_ADDED),
        // 119 was QueryPhaseExecutionException
        REPOSITORY_VERIFICATION_EXCEPTION(org.elasticsearch.repositories.RepositoryVerificationException.class,
                org.elasticsearch.repositories.RepositoryVerificationException::new, 120, UNKNOWN_VERSION_ADDED),
        // 121 was InvalidAggregationPathException
        // 123 used to be IndexAlreadyExistsException and was renamed
        RESOURCE_ALREADY_EXISTS_EXCEPTION(ResourceAlreadyExistsException.class,
            ResourceAlreadyExistsException::new, 123, UNKNOWN_VERSION_ADDED),
        // 124 used to be Script.ScriptParseException
        HTTP_REQUEST_ON_TRANSPORT_EXCEPTION(TcpTransport.HttpRequestOnTransportException.class,
                TcpTransport.HttpRequestOnTransportException::new, 125, UNKNOWN_VERSION_ADDED),
        MAPPER_PARSING_EXCEPTION(org.elasticsearch.index.mapper.MapperParsingException.class,
                org.elasticsearch.index.mapper.MapperParsingException::new, 126, UNKNOWN_VERSION_ADDED),
        // 127 was SearchContextException
        // 128 was SearchSourceBuilderException
        // 129 was EngineClosedException
        NO_SHARD_AVAILABLE_ACTION_EXCEPTION(org.elasticsearch.action.NoShardAvailableActionException.class,
                org.elasticsearch.action.NoShardAvailableActionException::new, 130, UNKNOWN_VERSION_ADDED),
        UNAVAILABLE_SHARDS_EXCEPTION(org.elasticsearch.action.UnavailableShardsException.class,
                org.elasticsearch.action.UnavailableShardsException::new, 131, UNKNOWN_VERSION_ADDED),
        FLUSH_FAILED_ENGINE_EXCEPTION(org.elasticsearch.index.engine.FlushFailedEngineException.class,
                org.elasticsearch.index.engine.FlushFailedEngineException::new, 132, UNKNOWN_VERSION_ADDED),
        CIRCUIT_BREAKING_EXCEPTION(org.elasticsearch.common.breaker.CircuitBreakingException.class,
                org.elasticsearch.common.breaker.CircuitBreakingException::new, 133, UNKNOWN_VERSION_ADDED),
        NODE_NOT_CONNECTED_EXCEPTION(org.elasticsearch.transport.NodeNotConnectedException.class,
                org.elasticsearch.transport.NodeNotConnectedException::new, 134, UNKNOWN_VERSION_ADDED),
        STRICT_DYNAMIC_MAPPING_EXCEPTION(org.elasticsearch.index.mapper.StrictDynamicMappingException.class,
                org.elasticsearch.index.mapper.StrictDynamicMappingException::new, 135, UNKNOWN_VERSION_ADDED),
        RETRY_ON_REPLICA_EXCEPTION(org.elasticsearch.action.support.replication.TransportReplicationAction.RetryOnReplicaException.class,
                org.elasticsearch.action.support.replication.TransportReplicationAction.RetryOnReplicaException::new, 136,
            UNKNOWN_VERSION_ADDED),
        TYPE_MISSING_EXCEPTION(org.elasticsearch.indices.TypeMissingException.class,
                org.elasticsearch.indices.TypeMissingException::new, 137, UNKNOWN_VERSION_ADDED),
        FAILED_TO_COMMIT_CLUSTER_STATE_EXCEPTION(org.elasticsearch.cluster.coordination.FailedToCommitClusterStateException.class,
                org.elasticsearch.cluster.coordination.FailedToCommitClusterStateException::new, 140, UNKNOWN_VERSION_ADDED),
        // 141 was QueryShardException
        NO_LONGER_PRIMARY_SHARD_EXCEPTION(ShardStateAction.NoLongerPrimaryShardException.class,
                ShardStateAction.NoLongerPrimaryShardException::new, 142, UNKNOWN_VERSION_ADDED),
        // 143 was ScriptException
        NOT_MASTER_EXCEPTION(org.elasticsearch.cluster.NotMasterException.class, org.elasticsearch.cluster.NotMasterException::new, 144,
            UNKNOWN_VERSION_ADDED),
        STATUS_EXCEPTION(org.elasticsearch.ElasticsearchStatusException.class, org.elasticsearch.ElasticsearchStatusException::new, 145,
            UNKNOWN_VERSION_ADDED),
        TASK_CANCELLED_EXCEPTION(org.elasticsearch.tasks.TaskCancelledException.class,
            org.elasticsearch.tasks.TaskCancelledException::new, 146, UNKNOWN_VERSION_ADDED),
        SHARD_LOCK_OBTAIN_FAILED_EXCEPTION(org.elasticsearch.env.ShardLockObtainFailedException.class,
                                           org.elasticsearch.env.ShardLockObtainFailedException::new, 147, UNKNOWN_VERSION_ADDED),
        // 148 was UnknownNamedObjectException
        // 149 was TooManyBucketsException
        COORDINATION_STATE_REJECTED_EXCEPTION(org.elasticsearch.cluster.coordination.CoordinationStateRejectedException.class,
            org.elasticsearch.cluster.coordination.CoordinationStateRejectedException::new, 150, Version.V_4_0_0),

        RETENTION_LEASE_ALREADY_EXISTS_EXCEPTION(
                org.elasticsearch.index.seqno.RetentionLeaseAlreadyExistsException.class,
                org.elasticsearch.index.seqno.RetentionLeaseAlreadyExistsException::new,
                153,
                Version.V_4_3_0),
        RETENTION_LEASE_NOT_FOUND_EXCEPTION(
                org.elasticsearch.index.seqno.RetentionLeaseNotFoundException.class,
                org.elasticsearch.index.seqno.RetentionLeaseNotFoundException::new,
                154,
                Version.V_4_3_0),
        SHARD_NOT_IN_PRIMARY_MODE_EXCEPTION(
                org.elasticsearch.index.shard.ShardNotInPrimaryModeException.class,
                org.elasticsearch.index.shard.ShardNotInPrimaryModeException::new,
                155,
                Version.V_4_3_0),
        JOB_KILLED_EXCEPTION(
            io.crate.exceptions.JobKilledException.class,
            io.crate.exceptions.JobKilledException::new,
                156,
            Version.V_4_3_0),
        TASK_MISSING_EXCEPTION(
            io.crate.exceptions.TaskMissing.class,
            io.crate.exceptions.TaskMissing::new,
                157,
            Version.V_4_3_0),
        RETENTION_LEASE_INVALID_RETAINING_SEQUENCE_NUMBER_EXCEPTION(
            org.elasticsearch.index.seqno.RetentionLeaseInvalidRetainingSeqNoException.class,
            org.elasticsearch.index.seqno.RetentionLeaseInvalidRetainingSeqNoException::new,
            158,
            Version.V_4_3_0),
        RELATION_ALREADY_EXISTS(
            io.crate.exceptions.RelationAlreadyExists.class,
            io.crate.exceptions.RelationAlreadyExists::new,
            159,
            Version.V_4_7_0),
        RELATION_UNKNOWN(
            io.crate.exceptions.RelationUnknown.class,
            io.crate.exceptions.RelationUnknown::new,
            160,
            Version.V_4_7_0),
        SCHEMA_UNKNOWN(
            io.crate.exceptions.SchemaUnknownException.class,
            io.crate.exceptions.SchemaUnknownException::new,
            161,
            Version.V_4_7_0),
        GROUP_BY_ON_ARRAY_UNSUPPORTED_EXCEPTION(
            ArrayViaDocValuesUnsupportedException.class,
            ArrayViaDocValuesUnsupportedException::new,
            162,
            Version.V_4_7_0),
        INVALID_ARGUMENT_EXCEPTION(
            io.crate.exceptions.InvalidArgumentException.class,
            io.crate.exceptions.InvalidArgumentException::new,
            163,
            Version.V_4_7_0),
        INVALID_COLUMN_NAME_EXCEPTION(
            io.crate.exceptions.InvalidColumnNameException.class,
            io.crate.exceptions.InvalidColumnNameException::new,
            164,
            Version.V_4_7_0),
        UNSUPPORTED_FEATURE_EXCEPTION(
            io.crate.exceptions.UnsupportedFeatureException.class,
            io.crate.exceptions.UnsupportedFeatureException::new,
            165,
            Version.V_4_7_0),
        USER_DEFINED_FUNCTION_ALREADY_EXISTS_EXCEPTION(
            io.crate.exceptions.UserDefinedFunctionAlreadyExistsException.class,
            io.crate.exceptions.UserDefinedFunctionAlreadyExistsException::new,
            166,
            Version.V_4_7_0),
        USER_DEFINED_FUNCTION_UNKNOWN_EXCEPTION(
            io.crate.exceptions.UserDefinedFunctionUnknownException.class,
            io.crate.exceptions.UserDefinedFunctionUnknownException::new,
            167,
            Version.V_4_7_0),
        VERSIONING_VALIDATION_EXCEPTION(
            io.crate.exceptions.VersioningValidationException.class,
            io.crate.exceptions.VersioningValidationException::new,
            168,
            Version.V_4_7_0),
        PUBLICATION_ALREADY_EXISTS_EXCEPTION(
            io.crate.replication.logical.exceptions.PublicationAlreadyExistsException.class,
            io.crate.replication.logical.exceptions.PublicationAlreadyExistsException::new,
            169,
            Version.V_4_7_0),
        PUBLICATION_UNKNOWN_EXCEPTION(
            io.crate.replication.logical.exceptions.PublicationUnknownException.class,
            io.crate.replication.logical.exceptions.PublicationUnknownException::new,
            170,
            Version.V_4_7_0),
        SUBSCRIPTION_ALREADY_EXISTS_EXCEPTION(
            io.crate.replication.logical.exceptions.SubscriptionAlreadyExistsException.class,
            io.crate.replication.logical.exceptions.SubscriptionAlreadyExistsException::new,
            171,
            Version.V_4_7_0),
        SUBSCRIPTION_UNKNOWN_EXCEPTION(
            io.crate.replication.logical.exceptions.SubscriptionUnknownException.class,
            io.crate.replication.logical.exceptions.SubscriptionUnknownException::new,
            172,
            Version.V_4_7_0),
        MISSING_SHARD_OPERATIONS_EXCEPTION(
            io.crate.replication.logical.exceptions.MissingShardOperationsException.class,
            io.crate.replication.logical.exceptions.MissingShardOperationsException::new,
            173,
            Version.V_4_7_0),
        PEER_RECOVERY_NOT_FOUND_EXCEPTION(
            org.elasticsearch.indices.recovery.PeerRecoveryNotFound.class,
            org.elasticsearch.indices.recovery.PeerRecoveryNotFound::new,
            174,
            Version.V_5_1_0),
        NODE_HEALTH_CHECK_FAILURE_EXCEPTION(
            org.elasticsearch.cluster.coordination.NodeHealthCheckFailureException.class,
            org.elasticsearch.cluster.coordination.NodeHealthCheckFailureException::new,
            175,
            Version.V_5_2_0),
        OPERATION_ON_INACCESSIBLE_RELATION_EXCEPTION(
            io.crate.exceptions.OperationOnInaccessibleRelationException.class,
            io.crate.exceptions.OperationOnInaccessibleRelationException::new,
            176,
            Version.V_5_6_0),
        UNAUTHORIZED_EXCEPTION(
            io.crate.exceptions.UnauthorizedException.class,
            io.crate.exceptions.UnauthorizedException::new,
            177,
            Version.V_5_7_0),
        SERVER_ALREADY_EXISTS(
            ServerAlreadyExistsException.class,
            ServerAlreadyExistsException::new,
            178,
            Version.V_5_7_0),
        USER_MAPPING_ALREADY_EXISTS(
            UserMappingAlreadyExists.class,
            UserMappingAlreadyExists::new,
            179,
            Version.V_5_7_0),
        ROLE_ALREADY_EXISTS(
            io.crate.exceptions.RoleAlreadyExistsException.class,
            io.crate.exceptions.RoleAlreadyExistsException::new,
            180,
            Version.V_5_7_0),
        ROLE_UNKNOWN(
            RoleUnknownException.class,
            RoleUnknownException::new,
            181,
            Version.V_5_7_0
        ),
        PRIMARY_SHARD_CLOSED_EXCEPTION(
            PrimaryShardClosedException.class,
            PrimaryShardClosedException::new,
            182,
            Version.V_6_0_0
        );

        final Class<? extends ElasticsearchException> exceptionClass;
        final CheckedFunction<StreamInput, ? extends ElasticsearchException, IOException> constructor;
        final int id;
        final Version versionAdded;

        <E extends ElasticsearchException> ElasticsearchExceptionHandle(Class<E> exceptionClass,
                                                                        CheckedFunction<StreamInput, E, IOException> constructor, int id,
                                                                        Version versionAdded) {
            // We need the exceptionClass because you can't dig it out of the constructor reliably.
            this.exceptionClass = exceptionClass;
            this.constructor = constructor;
            this.versionAdded = versionAdded;
            this.id = id;
        }
    }

    static {
        ID_TO_SUPPLIER = unmodifiableMap(Arrays
                .stream(ElasticsearchExceptionHandle.values()).collect(Collectors.toMap(e -> e.id, e -> e.constructor)));
        CLASS_TO_ELASTICSEARCH_EXCEPTION_HANDLE = unmodifiableMap(Arrays
                .stream(ElasticsearchExceptionHandle.values()).collect(Collectors.toMap(e -> e.exceptionClass, e -> e)));
    }

    public Index getIndex() {
        List<String> index = getMetadata(INDEX_METADATA_KEY);
        if (index != null && index.isEmpty() == false) {
            List<String> index_uuid = getMetadata(INDEX_METADATA_KEY_UUID);
            return new Index(index.get(0), index_uuid.get(0));
        }

        return null;
    }

    public ShardId getShardId() {
        List<String> shard = getMetadata(SHARD_METADATA_KEY);
        if (shard != null && shard.isEmpty() == false) {
            return new ShardId(getIndex(), Integer.parseInt(shard.get(0)));
        }
        return null;
    }

    public void setIndex(Index index) {
        if (index != null) {
            addMetadata(INDEX_METADATA_KEY, index.getName());
            addMetadata(INDEX_METADATA_KEY_UUID, index.getUUID());
        }
    }

    public void setIndex(String index) {
        if (index != null) {
            setIndex(new Index(index, INDEX_UUID_NA_VALUE));
        }
    }

    public void setShard(ShardId shardId) {
        if (shardId != null) {
            setIndex(shardId.getIndex());
            addMetadata(SHARD_METADATA_KEY, Integer.toString(shardId.id()));
        }
    }

    public void setResources(String type, String... id) {
        assert type != null;
        addMetadata(RESOURCE_METADATA_ID_KEY, id);
        addMetadata(RESOURCE_METADATA_TYPE_KEY, type);
    }
}
