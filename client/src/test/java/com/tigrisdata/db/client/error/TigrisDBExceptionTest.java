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
package com.tigrisdata.db.client.error;

import org.junit.Assert;
import org.junit.Test;

public class TigrisDBExceptionTest {

  @Test
  public void messageWithoutCauseTest() {
    TigrisDBException ex = new TigrisDBException("message1", null);
    Assert.assertEquals("message1", ex.getMessage());
  }

  @Test
  public void messageWithCauseMessageTest() {
    TigrisDBException ex = new TigrisDBException("message1", new Exception("message2"));
    Assert.assertEquals("message1 Cause: message2", ex.getMessage());
  }

  @Test
  public void messageWithCauseNullMessageTest() {
    TigrisDBException ex = new TigrisDBException("message1", new Exception((String) null));
    Assert.assertEquals("message1", ex.getMessage());
  }
}
