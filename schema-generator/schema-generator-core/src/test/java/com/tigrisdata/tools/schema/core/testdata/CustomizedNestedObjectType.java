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
package com.tigrisdata.tools.schema.core.testdata;

import com.tigrisdata.db.annotation.TigrisCollection;
import com.tigrisdata.db.annotation.TigrisField;

@TigrisCollection("CustomizedNestedObjectType")
public class CustomizedNestedObjectType {
  Product[] products;
  Seller[] sellers;
}

class Product {
  String name;
  int id;
  Category[] categories;
}

class Seller {
  String name;
  int id;
}

class Category {
  @TigrisField(description = "category name")
  String name;

  @TigrisField(description = "category image binary data")
  byte[] previewImage;

  String[] tags;
}
