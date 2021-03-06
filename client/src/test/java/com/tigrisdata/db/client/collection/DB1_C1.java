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
package com.tigrisdata.db.client.collection;

import com.tigrisdata.db.annotation.TigrisCollection;
import com.tigrisdata.db.type.TigrisCollectionType;

import java.util.Objects;

/** Test collection type */
@TigrisCollection("db1_c1")
public class DB1_C1 implements TigrisCollectionType {
  private final long id;
  private final String name;

  public DB1_C1(long id, String name) {
    this.id = id;
    this.name = name;
  }

  public long getId() {
    return id;
  }

  public String getName() {
    return name;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;

    DB1_C1 db1_c1 = (DB1_C1) o;

    if (id != db1_c1.id) return false;
    return Objects.equals(name, db1_c1.name);
  }

  @Override
  public int hashCode() {
    int result = (int) (id ^ (id >>> 32));
    result = 31 * result + (name != null ? name.hashCode() : 0);
    return result;
  }
}
