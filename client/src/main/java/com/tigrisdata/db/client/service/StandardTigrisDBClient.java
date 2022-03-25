package com.tigrisdata.db.client.service;

import com.tigrisdata.db.api.v1.grpc.Api;
import com.tigrisdata.db.api.v1.grpc.TigrisDBGrpc;
import com.tigrisdata.db.client.auth.AuthorizationToken;
import com.tigrisdata.db.client.config.TigrisDBConfiguration;
import com.tigrisdata.db.client.error.TigrisDBException;
import com.tigrisdata.db.client.interceptors.AuthHeaderInterceptor;
import com.tigrisdata.db.client.model.DatabaseOptions;
import com.tigrisdata.db.client.model.TigrisDBResponse;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.grpc.Metadata;
import io.grpc.stub.MetadataUtils;

import java.util.ArrayList;
import java.util.List;

public class StandardTigrisDBClient implements TigrisDBClient {

  private final AuthorizationToken authorizationToken;
  private final ManagedChannel channel;
  private final TigrisDBGrpc.TigrisDBBlockingStub stub;
  private static final Metadata.Key<String> USER_AGENT_KEY =
      Metadata.Key.of("user-agent", Metadata.ASCII_STRING_MARSHALLER);
  private static final Metadata.Key<String> CLIENT_VERSION_KEY =
      Metadata.Key.of("client-version", Metadata.ASCII_STRING_MARSHALLER);

  private static final String USER_AGENT_VALUE = "tigrisdb-client-java.grpc";
  private static final String CLIENT_VERSION_VALUE = "1.0";

  private StandardTigrisDBClient(
      TigrisDBConfiguration clientConfiguration, AuthorizationToken authorizationToken) {
    Metadata defaultHeaders = new Metadata();
    defaultHeaders.put(USER_AGENT_KEY, USER_AGENT_VALUE);
    defaultHeaders.put(CLIENT_VERSION_KEY, CLIENT_VERSION_VALUE);

    this.authorizationToken = authorizationToken;
    this.channel =
        ManagedChannelBuilder.forTarget(clientConfiguration.getBaseURL())
            .intercept(new AuthHeaderInterceptor(authorizationToken))
            .intercept(MetadataUtils.newAttachHeadersInterceptor(defaultHeaders))
            .build();
    this.stub = TigrisDBGrpc.newBlockingStub(channel);
  }

  // visible for testing
  StandardTigrisDBClient(
      AuthorizationToken authorizationToken,
      ManagedChannelBuilder<? extends ManagedChannelBuilder> managedChannelBuilder) {
    Metadata defaultHeaders = new Metadata();
    defaultHeaders.put(USER_AGENT_KEY, USER_AGENT_VALUE);
    defaultHeaders.put(CLIENT_VERSION_KEY, CLIENT_VERSION_VALUE);

    this.authorizationToken = authorizationToken;
    this.channel =
        managedChannelBuilder
            .intercept(new AuthHeaderInterceptor(authorizationToken))
            .intercept(MetadataUtils.newAttachHeadersInterceptor(defaultHeaders))
            .build();
    this.stub = TigrisDBGrpc.newBlockingStub(channel);
  }

  public static StandardTigrisDBClient getInstance(
      AuthorizationToken authorizationToken, TigrisDBConfiguration tigrisDBConfiguration) {
    return new StandardTigrisDBClient(tigrisDBConfiguration, authorizationToken);
  }

  @Override
  public TigrisDatabase getDatabase(String databaseName) {
    return new StandardTigrisDatabase(databaseName, stub, channel);
  }

  @Override
  public List<TigrisDatabase> listDatabases(DatabaseOptions listDatabaseOptions)
      throws TigrisDBException {
    Api.ListDatabasesRequest listDatabasesRequest = Api.ListDatabasesRequest.newBuilder().build();
    Api.ListDatabasesResponse listDatabasesResponse = stub.listDatabases(listDatabasesRequest);
    List<TigrisDatabase> dbs = new ArrayList<>();
    for (String s : listDatabasesResponse.getDbsList()) {
      dbs.add(new StandardTigrisDatabase(s, stub, channel));
    }
    return dbs;
  }

  @Override
  public TigrisDBResponse createDatabase(String databaseName, DatabaseOptions databaseOptions)
      throws TigrisDBException {
    Api.CreateDatabaseRequest createDatabaseRequest =
        Api.CreateDatabaseRequest.newBuilder()
            .setDb(databaseName)
            .setOptions(Api.DatabaseOptions.newBuilder().build())
            .build();
    Api.CreateDatabaseResponse createDatabaseResponse = stub.createDatabase(createDatabaseRequest);
    return new TigrisDBResponse(createDatabaseResponse.getMsg());
  }

  @Override
  public TigrisDBResponse dropDatabase(String databaseName, DatabaseOptions databaseOptions)
      throws TigrisDBException {
    Api.DropDatabaseRequest dropDatabaseRequest =
        Api.DropDatabaseRequest.newBuilder()
            .setDb(databaseName)
            .setOptions(Api.DatabaseOptions.newBuilder().build())
            .build();
    Api.DropDatabaseResponse dropDatabaseResponse = stub.dropDatabase(dropDatabaseRequest);
    return new TigrisDBResponse(dropDatabaseResponse.getMsg());
  }

  @Override
  public void close() {
    channel.shutdown();
  }

  // visible for testing
  ManagedChannel getChannel() {
    return channel;
  }
}
