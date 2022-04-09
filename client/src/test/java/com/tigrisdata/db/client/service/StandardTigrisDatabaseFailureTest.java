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
package com.tigrisdata.db.client.service;

import com.tigrisdata.db.client.error.TigrisDBException;
import com.tigrisdata.db.client.grpc.FailingTestUserService;
import com.tigrisdata.db.client.model.TransactionOptions;
import io.grpc.Status;
import io.grpc.inprocess.InProcessServerBuilder;
import io.grpc.testing.GrpcCleanupRule;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;

import java.io.IOException;
import java.net.URL;
import java.util.Collections;
import java.util.UUID;

public class StandardTigrisDatabaseFailureTest {
  private static String SERVER_NAME;
  @ClassRule public static final GrpcCleanupRule grpcCleanup = new GrpcCleanupRule();

  @BeforeClass
  public static void setup() throws Exception {
    SERVER_NAME = InProcessServerBuilder.generateName();
    grpcCleanup
        .register(
            InProcessServerBuilder.forName(SERVER_NAME)
                .directExecutor()
                .addService(new FailingTestUserService())
                .build())
        .start();
  }

  @Test
  public void testListCollections() {
    TigrisDBClient client = TestUtils.getTestClient(SERVER_NAME, grpcCleanup);
    String dbName = UUID.randomUUID().toString();
    TigrisDatabase db1 = client.getDatabase(dbName);
    try {
      db1.listCollections();
      Assert.fail("This must fail");
    } catch (TigrisDBException tigrisDBException) {
      Assert.assertEquals(
          "Failed to list collection(s) Cause: FAILED_PRECONDITION: Test failure " + dbName,
          tigrisDBException.getMessage());
      Assert.assertEquals(
          Status.fromThrowable(tigrisDBException.getCause()).getCode(),
          Status.FAILED_PRECONDITION.getCode());
    }
  }

  @Test
  public void testCreateCollectionFromURLs() throws IOException {
    TigrisDBClient client = TestUtils.getTestClient(SERVER_NAME, grpcCleanup);
    String dbName = UUID.randomUUID().toString();
    TigrisDatabase db1 = client.getDatabase(dbName);
    try {
      db1.createCollectionsInTransaction(
          Collections.singletonList(new URL("file:src/test/resources/db1_c5.json")));
      Assert.fail("This must fail");
    } catch (TigrisDBException tigrisDBException) {
      Assert.assertEquals(
          "Failed to create collections in transaction Cause: Failed to begin transaction Cause: FAILED_PRECONDITION: Test failure "
              + dbName,
          tigrisDBException.getMessage());
      Assert.assertEquals(
          Status.fromThrowable(tigrisDBException.getCause()).getCode(),
          Status.FAILED_PRECONDITION.getCode());
    }
  }

  /**
   * pass begin transaction, fail during createOrUpdateCollection, then rollback the transaction
   *
   * @throws IOException
   */
  @Test
  public void testCreateCollectionFromURLsFailAndRollback() throws IOException {
    TigrisDBClient client = TestUtils.getTestClient(SERVER_NAME, grpcCleanup);
    String dbName =
        FailingTestUserService.ALLOW_BEGIN_TRANSACTION_DB_NAME
            + ","
            + FailingTestUserService.ALLOW_ROLLBACK_TRANSACTION_DB_NAME;
    TigrisDatabase db1 = client.getDatabase(dbName);
    try {
      db1.createCollectionsInTransaction(
          Collections.singletonList(new URL("file:src/test/resources/db1_c5.json")));
      Assert.fail("This must fail");
    } catch (TigrisDBException tigrisDBException) {
      Assert.assertEquals(
          "Failed to create collections in transaction Cause: Failed to create collection in transactional session Cause: FAILED_PRECONDITION: Test failure pass-begin,pass-rollback",
          tigrisDBException.getMessage());
      Assert.assertEquals(
          Status.fromThrowable(tigrisDBException.getCause()).getCode(),
          Status.FAILED_PRECONDITION.getCode());
    }
  }

  @Test
  public void testDropCollection() {
    TigrisDBClient client = TestUtils.getTestClient(SERVER_NAME, grpcCleanup);
    String dbName = UUID.randomUUID().toString();

    TigrisDatabase db1 = client.getDatabase(dbName);
    try {
      db1.dropCollection("db1_c3");
      Assert.fail("This must fail");
    } catch (TigrisDBException tigrisDBException) {
      Assert.assertEquals(
          "Failed to drop collection Cause: FAILED_PRECONDITION: Test failure " + dbName,
          tigrisDBException.getMessage());
      Assert.assertEquals(
          Status.fromThrowable(tigrisDBException.getCause()).getCode(),
          Status.FAILED_PRECONDITION.getCode());
    }
  }

  @Test
  public void testBeginTransaction() {
    String dbName = UUID.randomUUID().toString();

    TigrisDBClient client = TestUtils.getTestClient(SERVER_NAME, grpcCleanup);
    TigrisDatabase db = client.getDatabase(dbName);
    try {
      db.beginTransaction(new TransactionOptions());
      Assert.fail("This must fail");
    } catch (TigrisDBException tigrisDBException) {
      Assert.assertEquals(
          "Failed to begin transaction Cause: FAILED_PRECONDITION: Test failure " + dbName,
          tigrisDBException.getMessage());
      Assert.assertEquals(
          Status.fromThrowable(tigrisDBException.getCause()).getCode(),
          Status.FAILED_PRECONDITION.getCode());
    }
  }

  @Test
  public void testCommitTransaction() {
    String dbName = FailingTestUserService.ALLOW_BEGIN_TRANSACTION_DB_NAME;
    TigrisDBClient client = TestUtils.getTestClient(SERVER_NAME, grpcCleanup);
    TigrisDatabase db = client.getDatabase(dbName);
    try {
      TransactionSession transactionSession = db.beginTransaction(new TransactionOptions());
      Assert.assertNotNull(transactionSession);
      transactionSession.commit();
      Assert.fail("commit() must fail");
    } catch (TigrisDBException tigrisDBException) {
      Assert.assertEquals(
          "Failed to commit transaction Cause: FAILED_PRECONDITION: Test failure " + dbName,
          tigrisDBException.getMessage());
      Assert.assertEquals(
          Status.fromThrowable(tigrisDBException.getCause()).getCode(),
          Status.FAILED_PRECONDITION.getCode());
    }
  }

  @Test
  public void testRollbackTransaction() {
    String dbName = FailingTestUserService.ALLOW_BEGIN_TRANSACTION_DB_NAME;
    TigrisDBClient client = TestUtils.getTestClient(SERVER_NAME, grpcCleanup);
    TigrisDatabase db = client.getDatabase(dbName);
    try {
      TransactionSession transactionSession = db.beginTransaction(new TransactionOptions());
      Assert.assertNotNull(transactionSession);
      transactionSession.rollback();
      Assert.fail("rollback() must fail");
    } catch (TigrisDBException tigrisDBException) {
      Assert.assertEquals(
          "Failed to rollback transaction Cause: FAILED_PRECONDITION: Test failure " + dbName,
          tigrisDBException.getMessage());
      Assert.assertEquals(
          Status.fromThrowable(tigrisDBException.getCause()).getCode(),
          Status.FAILED_PRECONDITION.getCode());
    }
  }
}