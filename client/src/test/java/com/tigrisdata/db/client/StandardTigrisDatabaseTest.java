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

import com.tigrisdata.db.client.error.TigrisDBException;
import com.tigrisdata.db.client.grpc.TestUserService;
import io.grpc.inprocess.InProcessServerBuilder;
import io.grpc.testing.GrpcCleanupRule;
import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.After;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

public class StandardTigrisDatabaseTest {
  private static String SERVER_NAME;
  private static TestUserService TEST_USER_SERVICE;
  @ClassRule public static final GrpcCleanupRule grpcCleanup = new GrpcCleanupRule();

  @BeforeClass
  public static void setup() throws Exception {
    SERVER_NAME = InProcessServerBuilder.generateName();
    TEST_USER_SERVICE = new TestUserService();
    grpcCleanup
        .register(
            InProcessServerBuilder.forName(SERVER_NAME)
                .directExecutor()
                .addService(TEST_USER_SERVICE)
                .build())
        .start();
  }

  @After
  public void reset() {
    TEST_USER_SERVICE.reset();
  }

  @Test
  public void testListCollections() throws TigrisDBException {
    TigrisDBClient client = TestUtils.getTestClient(SERVER_NAME, grpcCleanup);
    TigrisDatabase db1 = client.getDatabase("db1");
    List<CollectionInfo> collections = db1.listCollections();
    Assert.assertEquals(5, collections.size());
    MatcherAssert.assertThat(
        collections,
        Matchers.containsInAnyOrder(
            new CollectionInfo("db1_c0"),
            new CollectionInfo("db1_c1"),
            new CollectionInfo("db1_c2"),
            new CollectionInfo("db1_c3"),
            new CollectionInfo("db1_c4")));
  }

  @Test
  public void testCreateCollectionFromURLs() throws TigrisDBException, IOException {
    TigrisDBClient client = TestUtils.getTestClient(SERVER_NAME, grpcCleanup);
    TigrisDatabase db1 = client.getDatabase("db1");
    TigrisDBResponse response =
        db1.createCollectionsInTransaction(
            Collections.singletonList(new URL("file:src/test/resources/db1_c5.json")));
    Assert.assertEquals("Collections creates successfully", response.getMessage());
    MatcherAssert.assertThat(
        db1.listCollections(),
        Matchers.containsInAnyOrder(
            new CollectionInfo("db1_c0"),
            new CollectionInfo("db1_c1"),
            new CollectionInfo("db1_c2"),
            new CollectionInfo("db1_c3"),
            new CollectionInfo("db1_c4"),
            new CollectionInfo("db1_c5")));
  }

  @Test
  public void testCreateCollectionFromDir() throws TigrisDBException {
    TigrisDBClient client = TestUtils.getTestClient(SERVER_NAME, grpcCleanup);
    TigrisDatabase db1 = client.getDatabase("db1");
    TigrisDBResponse response =
        db1.createCollectionsInTransaction(new File("src/test/resources/test-dir"));
    Assert.assertEquals("Collections creates successfully", response.getMessage());
    MatcherAssert.assertThat(
        db1.listCollections(),
        Matchers.containsInAnyOrder(
            new CollectionInfo("db1_c0"),
            new CollectionInfo("db1_c1"),
            new CollectionInfo("db1_c2"),
            new CollectionInfo("db1_c3"),
            new CollectionInfo("db1_c4"),
            new CollectionInfo("db1_c5"),
            new CollectionInfo("db1_c6")));
  }

  @Test
  public void testCreateCollectionFromNonExistingDir() {
    TigrisDBClient client = TestUtils.getTestClient(SERVER_NAME, grpcCleanup);
    TigrisDatabase db1 = client.getDatabase("db1");
    try {
      db1.createCollectionsInTransaction(
          new File("/" + UUID.randomUUID() + "/" + UUID.randomUUID()));
      Assert.fail("This must fail");
    } catch (TigrisDBException tigrisDBException) {
      System.out.println(tigrisDBException.getMessage());
      Assert.assertTrue(
          tigrisDBException.getMessage().startsWith("Failed to process schemaDirectory"));
    }
  }

  @Test
  public void testDropCollection() throws TigrisDBException {
    TigrisDBClient client = TestUtils.getTestClient(SERVER_NAME, grpcCleanup);
    TigrisDatabase db1 = client.getDatabase("db1");
    DropCollectionResponse response = db1.dropCollection("db1_c3");
    Assert.assertEquals("db1_c3 dropped", response.getTigrisDBResponse().getMessage());
    MatcherAssert.assertThat(
        db1.listCollections(),
        Matchers.containsInAnyOrder(
            new CollectionInfo("db1_c0"),
            new CollectionInfo("db1_c1"),
            new CollectionInfo("db1_c2"),
            new CollectionInfo("db1_c4")));
  }

  @Test
  public void testGetCollection() {
    TigrisDBClient client = TestUtils.getTestClient(SERVER_NAME, grpcCleanup);
    TigrisDatabase db1 = client.getDatabase("db1");
    TigrisCollection<DB1_C1> c1TigrisCollection = db1.getCollection(DB1_C1.class);
    Assert.assertEquals("db1_c1", c1TigrisCollection.name());
  }

  @Test
  public void testBeginTransaction() throws TigrisDBException {
    TigrisDBClient client = TestUtils.getTestClient(SERVER_NAME, grpcCleanup);
    TigrisDatabase db1 = client.getDatabase("db1");
    TransactionSession transactionSession = db1.beginTransaction(new TransactionOptions());
    transactionSession.commit();
  }

  @Test
  public void testCommitTransaction() throws TigrisDBException {
    TigrisDBClient client = TestUtils.getTestClient(SERVER_NAME, grpcCleanup);
    TigrisDatabase db1 = client.getDatabase("db1");
    TransactionSession transactionSession = db1.beginTransaction(new TransactionOptions());
    transactionSession.commit();
  }

  @Test
  public void testRollbackTransaction() throws TigrisDBException {
    TigrisDBClient client = TestUtils.getTestClient(SERVER_NAME, grpcCleanup);
    TigrisDatabase db1 = client.getDatabase("db1");
    TransactionSession transactionSession = db1.beginTransaction(new TransactionOptions());
    transactionSession.rollback();
  }

  @Test
  public void testName() {
    TigrisDBClient client = TestUtils.getTestClient(SERVER_NAME, grpcCleanup);
    TigrisDatabase db1 = client.getDatabase("db1");
    Assert.assertEquals("db1", db1.name());
  }

  @Test
  public void testToString() {
    TigrisDBClient client = TestUtils.getTestClient(SERVER_NAME, grpcCleanup);
    TigrisDatabase db1 = client.getDatabase("db1");
    Assert.assertEquals("StandardTigrisDatabase{dbName='db1'}", db1.toString());
  }

  @Test
  public void testHashcode() {
    TigrisDBClient client = TestUtils.getTestClient(SERVER_NAME, grpcCleanup);
    TigrisDatabase db11 = client.getDatabase("db1");
    TigrisDatabase db12 = client.getDatabase("db1");
    Assert.assertEquals(db11.hashCode(), db12.hashCode());

    // null dbName resolves to 0 hashcode
    Assert.assertEquals(0, new StandardTigrisDatabase(null, null, null, null).hashCode());
  }

  @Test
  public void testEquals() {
    TigrisDatabase db1 = new StandardTigrisDatabase("db1", null, null, null);
    TigrisDatabase db2 = new StandardTigrisDatabase("db1", null, null, null);
    Assert.assertTrue(db1.equals(db2));
    Assert.assertTrue(db1.equals(db1));

    Assert.assertFalse(db1.equals(null));
    Assert.assertFalse(db1.equals("string-obj"));
  }
}