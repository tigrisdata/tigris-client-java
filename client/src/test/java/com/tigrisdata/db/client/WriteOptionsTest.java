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

import org.junit.Assert;
import org.junit.Test;

public class WriteOptionsTest {

  @Test
  public void testEquals() {
    WriteOptions writeOptions1 = WriteOptions.DEFAULT_INSTANCE;
    WriteOptions writeOptions2 = WriteOptions.DEFAULT_INSTANCE;
    Assert.assertEquals(writeOptions1, writeOptions1);
    Assert.assertEquals(writeOptions1, writeOptions2);

    Assert.assertFalse(writeOptions1.equals(null));
    Assert.assertFalse(writeOptions1.equals("some-string"));
  }

  @Test
  public void testHashCode() {
    WriteOptions writeOptions1 = WriteOptions.DEFAULT_INSTANCE;
    WriteOptions writeOptions2 = WriteOptions.DEFAULT_INSTANCE;
    Assert.assertEquals(writeOptions1.hashCode(), writeOptions2.hashCode());
  }
}
