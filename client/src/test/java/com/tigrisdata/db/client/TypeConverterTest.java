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

import com.tigrisdata.db.api.v1.grpc.Api;
import com.tigrisdata.db.client.error.TigrisException;
import org.junit.Assert;
import org.junit.Test;

import java.util.Optional;

public class TypeConverterTest {
  @Test
  public void apiDatabaseInfoToModelTest() {
    DatabaseInfo convertedDatabaseInfo1 =
        TypeConverter.toDatabaseInfo(Api.DatabaseInfo.newBuilder().setDb("db1").build());
    DatabaseInfo databaseInfo1 = new DatabaseInfo("db1");
    Assert.assertEquals(convertedDatabaseInfo1, databaseInfo1);
  }

  @Test
  public void apiCollectionInfoToModelTest() {
    CollectionInfo convertedCollectionInfo1 =
        TypeConverter.toCollectionInfo(Api.CollectionInfo.newBuilder().setCollection("c1").build());
    CollectionInfo collectionInfo1 = new CollectionInfo("c1");
    Assert.assertEquals(convertedCollectionInfo1, collectionInfo1);
  }

  @Test
  public void unreadableSchemaCreateCollectionRequestConversionTest() {
    try {
      TypeConverter.toCreateCollectionRequest(
          "db1",
          new TigrisJSONSchema("invalid-schema"),
          CollectionOptions.DEFAULT_INSTANCE,
          Optional.empty());
      Assert.fail("This must fail");
    } catch (TigrisException ignore) {
    }
  }
}
