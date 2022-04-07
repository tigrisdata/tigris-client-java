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
import com.tigrisdata.db.client.model.DeleteRequestOptions;
import com.tigrisdata.db.client.model.DeleteResponse;
import com.tigrisdata.db.client.model.InsertOrReplaceRequestOptions;
import com.tigrisdata.db.client.model.InsertOrReplaceResponse;
import com.tigrisdata.db.client.model.InsertRequestOptions;
import com.tigrisdata.db.client.model.InsertResponse;
import com.tigrisdata.db.client.model.ReadFields;
import com.tigrisdata.db.client.model.ReadRequestOptions;
import com.tigrisdata.db.client.model.TigrisCollectionType;
import com.tigrisdata.db.client.model.TigrisFilter;
import com.tigrisdata.db.client.model.UpdateFields;
import com.tigrisdata.db.client.model.UpdateRequestOptions;
import com.tigrisdata.db.client.model.UpdateResponse;

import java.util.Iterator;
import java.util.List;
import java.util.Optional;

public interface TigrisCollection<T extends TigrisCollectionType> {

  /**
   * @param filter filter to narrow down read
   * @param fields optionally specify fields you want to be returned from server
   * @param readRequestOptions read options
   * @return stream of documents
   * @throws TigrisDBException
   */
  Iterator<T> read(TigrisFilter filter, ReadFields fields, ReadRequestOptions readRequestOptions)
      throws TigrisDBException;

  /**
   * Reads matching documents
   *
   * @param filter filter to narrow down read
   * @param fields optionally specify fields you want to be returned from server
   * @return stream of documents
   * @throws TigrisDBException in case of an error
   */
  Iterator<T> read(TigrisFilter filter, ReadFields fields) throws TigrisDBException;

  /**
   * Reads a single document. This method is generally recommended for point lookup, if used for
   * non-point lookup any arbitrary matching document will be returned.
   *
   * @param filter
   * @return Optional of document.
   * @throws TigrisDBException
   */
  Optional<T> readOne(TigrisFilter filter) throws TigrisDBException;

  /**
   * @param documents list of documents to insert
   * @param insertRequestOptions insert option
   * @return an instance of {@link InsertResponse} from server
   * @throws TigrisDBException in case of an error
   */
  InsertResponse insert(List<T> documents, InsertRequestOptions insertRequestOptions)
      throws TigrisDBException;

  /**
   * @param documents list of documents to insert
   * @return an instance of {@link InsertResponse} from server
   * @throws TigrisDBException in case of an error
   */
  InsertResponse insert(List<T> documents) throws TigrisDBException;

  /**
   * Inserts the documents if they don't exist already, replaces them otherwise.
   *
   * @param documents list of documents to replace
   * @param insertOrReplaceRequestOptions option
   * @return an instance of {@link InsertOrReplaceResponse} from server
   * @throws TigrisDBException in case of an error
   */
  InsertOrReplaceResponse insertOrReplace(
      List<T> documents, InsertOrReplaceRequestOptions insertOrReplaceRequestOptions)
      throws TigrisDBException;

  /**
   * Inserts the documents if they don't exist already, replaces them otherwise.
   *
   * @param documents list of documents to replace
   * @return an instance of {@link InsertOrReplaceResponse} from server
   * @throws TigrisDBException in case of an error
   */
  InsertOrReplaceResponse insertOrReplace(List<T> documents) throws TigrisDBException;

  /**
   * inserts a single document to the collection
   *
   * @param document
   * @return
   * @throws TigrisDBException
   */
  InsertResponse insert(T document) throws TigrisDBException;

  /**
   * @param filter
   * @param updateFields
   * @param updateRequestOptions
   * @return
   * @throws TigrisDBException
   */
  UpdateResponse update(
      TigrisFilter filter, UpdateFields updateFields, UpdateRequestOptions updateRequestOptions)
      throws TigrisDBException;

  /**
   * @param filter
   * @param updateFields
   * @return
   * @throws TigrisDBException
   */
  UpdateResponse update(TigrisFilter filter, UpdateFields updateFields) throws TigrisDBException;

  /**
   * Deletes the matching documents in the collection.
   *
   * @param filter filter to narrow down the documents to delete
   * @param deleteRequestOptions delete option
   * @return an instance of {@link DeleteResponse} from server
   * @throws TigrisDBException in case of an error
   */
  DeleteResponse delete(TigrisFilter filter, DeleteRequestOptions deleteRequestOptions)
      throws TigrisDBException;

  /**
   * Deletes the matching documents in the collection.
   *
   * @param filter filter to narrow down the documents to delete
   * @return an instance of {@link DeleteResponse} from server
   * @throws TigrisDBException in case of an error
   */
  DeleteResponse delete(TigrisFilter filter) throws TigrisDBException;

  /** @return Name of the collection */
  String name();
}
