/*
 * Copyright 2022 Tigris Data, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the
 * License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.tigrisdata.db.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.util.concurrent.ListenableFuture;
import com.tigrisdata.db.api.v1.grpc.Api;
import com.tigrisdata.db.api.v1.grpc.TigrisDBGrpc;
import static com.tigrisdata.db.client.ErrorMessages.BEGIN_TRANSACTION_FAILED;
import static com.tigrisdata.db.client.ErrorMessages.CREATE_OR_UPDATE_COLLECTION_FAILED;
import static com.tigrisdata.db.client.ErrorMessages.DROP_COLLECTION_FAILED;
import static com.tigrisdata.db.client.ErrorMessages.LIST_COLLECTION_FAILED;
import static com.tigrisdata.db.client.TypeConverter.toBeginTransactionRequest;
import static com.tigrisdata.db.client.TypeConverter.toCreateCollectionRequest;
import static com.tigrisdata.db.client.TypeConverter.toDropCollectionRequest;
import com.tigrisdata.db.client.error.TigrisDBException;
import io.grpc.ManagedChannel;

import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.stream.Collectors;

/** Async implementation of TigrisDB */
public class StandardTigrisAsyncDatabase implements TigrisAsyncDatabase {
  private final String databaseName;
  private final TigrisDBGrpc.TigrisDBFutureStub stub;
  private final ManagedChannel channel;
  private final Executor executor;
  private final ObjectMapper objectMapper;

  StandardTigrisAsyncDatabase(
      String databaseName,
      TigrisDBGrpc.TigrisDBFutureStub stub,
      ManagedChannel channel,
      Executor executor,
      ObjectMapper objectMapper) {
    this.stub = stub;
    this.channel = channel;
    this.databaseName = databaseName;
    this.executor = executor;
    this.objectMapper = objectMapper;
  }

  @Override
  public CompletableFuture<List<CollectionInfo>> listCollections() {
    ListenableFuture<Api.ListCollectionsResponse> listListenableFuture =
        stub.listCollections(
            Api.ListCollectionsRequest.newBuilder().setDb(this.databaseName).build());
    return Utilities.transformFuture(
        listListenableFuture,
        listCollectionsResponse ->
            listCollectionsResponse.getCollectionsList().stream()
                .map(TypeConverter::toCollectionInfo)
                .collect(Collectors.toList()),
        executor,
        LIST_COLLECTION_FAILED);
  }

  @Override
  public CompletableFuture<CreateOrUpdateCollectionResponse> createOrUpdateCollection(
      TigrisDBSchema schema, CollectionOptions collectionOptions) throws TigrisDBException {
    ListenableFuture<Api.CreateOrUpdateCollectionResponse>
        createCollectionResponseListenableFuture =
            stub.createOrUpdateCollection(
                toCreateCollectionRequest(
                    databaseName, schema, collectionOptions, Optional.empty()));
    return Utilities.transformFuture(
        createCollectionResponseListenableFuture,
        (input) -> new CreateOrUpdateCollectionResponse(new TigrisDBResponse(input.getMsg())),
        executor,
        CREATE_OR_UPDATE_COLLECTION_FAILED);
  }

  @Override
  public CompletableFuture<DropCollectionResponse> dropCollection(String collectionName) {
    // TODO: pull CollectionsOut in API
    ListenableFuture<Api.DropCollectionResponse> dropCollectionResponseListenableFuture =
        stub.dropCollection(
            toDropCollectionRequest(
                databaseName,
                collectionName,
                CollectionOptions.DEFAULT_INSTANCE,
                Optional.empty()));
    return Utilities.transformFuture(
        dropCollectionResponseListenableFuture,
        input -> new DropCollectionResponse(new TigrisDBResponse(input.getMsg())),
        executor,
        DROP_COLLECTION_FAILED);
  }

  @Override
  public <C extends TigrisCollectionType> TigrisAsyncCollection<C> getCollection(
      Class<C> collectionTypeClass) {
    return new StandardTigrisAsyncCollection<>(
        databaseName, collectionTypeClass, channel, executor, objectMapper);
  }

  @Override
  public CompletableFuture<TransactionSession> beginTransaction(
      TransactionOptions transactionOptions) {
    ListenableFuture<Api.BeginTransactionResponse> beginTransactionResponseListenableFuture =
        stub.beginTransaction(toBeginTransactionRequest(databaseName, transactionOptions));
    return Utilities.transformFuture(
        beginTransactionResponseListenableFuture,
        input ->
            new StandardTransactionSession(databaseName, input.getTxCtx(), channel, objectMapper),
        executor,
        BEGIN_TRANSACTION_FAILED);
  }

  @Override
  public String name() {
    return databaseName;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;

    StandardTigrisAsyncDatabase that = (StandardTigrisAsyncDatabase) o;

    return Objects.equals(databaseName, that.databaseName);
  }

  @Override
  public int hashCode() {
    return databaseName != null ? databaseName.hashCode() : 0;
  }

  @Override
  public String toString() {
    return "StandardTigrisAsyncDatabase{" + "databaseName='" + databaseName + '\'' + '}';
  }
}