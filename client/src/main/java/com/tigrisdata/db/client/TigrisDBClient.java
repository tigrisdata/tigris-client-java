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

import java.io.Closeable;
import java.util.List;

/** TigrisDB client */
public interface TigrisDBClient extends Closeable {

  /**
   * Retrieves the database instance
   *
   * @param databaseName databaseName
   * @return an instance of {@link TigrisDatabase}
   */
  TigrisDatabase getDatabase(String databaseName);

  /**
   * Lists the available databases for the current Api.
   *
   * @param listDatabaseOptions options
   * @return a list of @{@link TigrisDatabase}
   * @throws TigrisDBException authentication failure or any other error
   */
  List<TigrisDatabase> listDatabases(DatabaseOptions listDatabaseOptions) throws TigrisDBException;

  /**
   * Creates the database if the database is not already present
   *
   * @param databaseName name of the database
   * @param databaseOptions options
   * @return an instance of {@link TigrisDBResponse} from server
   * @throws TigrisDBException in case of auth error or any other failure.
   */
  TigrisDBResponse createDatabaseIfNotExists(String databaseName, DatabaseOptions databaseOptions)
      throws TigrisDBException;

  /**
   * Drops the database
   *
   * @param databaseName name of the database
   * @param databaseOptions options
   * @return an instance of {@link TigrisDBResponse} from server
   * @throws TigrisDBException in case of auth error or any other failure.
   */
  TigrisDBResponse dropDatabase(String databaseName, DatabaseOptions databaseOptions)
      throws TigrisDBException;
}