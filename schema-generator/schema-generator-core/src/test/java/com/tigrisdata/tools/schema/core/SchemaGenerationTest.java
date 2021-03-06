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
package com.tigrisdata.tools.schema.core;

import com.tigrisdata.tools.schema.core.testdata.ArrayFields;
import com.tigrisdata.tools.schema.core.testdata.ArrayOfCustomType;
import com.tigrisdata.tools.schema.core.testdata.BoxedTypes;
import com.tigrisdata.tools.schema.core.testdata.ByteArrayMultiDimensional;
import com.tigrisdata.tools.schema.core.testdata.CustomizedNestedObjectType;
import com.tigrisdata.tools.schema.core.testdata.EnumTypes;
import com.tigrisdata.tools.schema.core.testdata.NestedObjectTypes;
import com.tigrisdata.tools.schema.core.testdata.PrimaryKeyWithAutoGeneration1;
import com.tigrisdata.tools.schema.core.testdata.PrimaryKeyWithAutoGeneration2;
import com.tigrisdata.tools.schema.core.testdata.PrimaryKeyWithAutoGeneration3;
import com.tigrisdata.tools.schema.core.testdata.PrimaryKeyWithAutoGeneration4;
import com.tigrisdata.tools.schema.core.testdata.PrimaryKeyWithAutoGeneration5;
import com.tigrisdata.tools.schema.core.testdata.PrimaryKeyWithAutoGeneration6;
import com.tigrisdata.tools.schema.core.testdata.PrimaryKeyWithAutoGeneration7;
import com.tigrisdata.tools.schema.core.testdata.PrimaryKeyWithAutoGeneration8;
import com.tigrisdata.tools.schema.core.testdata.PrimitiveTypes;
import com.tigrisdata.tools.schema.core.testdata.TigrisCustomTypes;
import org.junit.Assert;
import org.junit.Test;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

public class SchemaGenerationTest {

  @Test
  public void testPrimitiveTypes() throws Exception {
    compareSchema(PrimitiveTypes.class);
  }

  @Test
  public void testBoxedTypes() throws Exception {
    compareSchema(BoxedTypes.class);
  }

  @Test
  public void testEnumTypes() throws Exception {
    compareSchema(EnumTypes.class);
  }

  @Test
  public void testCustomTypes() throws Exception {
    compareSchema(TigrisCustomTypes.class);
  }

  @Test
  public void testArrayFields() throws Exception {
    compareSchema(ArrayFields.class);
  }

  @Test
  public void testNestedObjectTypes() throws Exception {
    compareSchema(NestedObjectTypes.class);
  }

  @Test
  public void testArrayOfCustomType() throws Exception {
    compareSchema(ArrayOfCustomType.class);
  }

  @Test
  public void testCustomizedNestedObjectType() throws Exception {
    compareSchema(CustomizedNestedObjectType.class);
  }

  @Test
  public void testByteArrayMultiDimensional() throws Exception {
    compareSchema(ByteArrayMultiDimensional.class);
  }

  @Test
  public void testPrimaryKeyWithAutoGeneration1() throws Exception {
    compareSchema(PrimaryKeyWithAutoGeneration1.class);
  }

  @Test
  public void testPrimaryKeyWithAutoGeneration2() throws Exception {
    compareSchema(PrimaryKeyWithAutoGeneration2.class);
  }

  @Test
  public void testPrimaryKeyWithAutoGeneration3() throws Exception {
    compareSchema(PrimaryKeyWithAutoGeneration3.class);
  }

  @Test
  public void testPrimaryKeyWithAutoGeneration4() throws Exception {
    compareSchema(PrimaryKeyWithAutoGeneration4.class);
  }

  @Test
  public void testPrimaryKeyWithAutoGeneration5() throws Exception {
    compareSchema(PrimaryKeyWithAutoGeneration5.class);
  }

  @Test
  public void testPrimaryKeyWithAutoGeneration6() throws Exception {
    compareSchema(PrimaryKeyWithAutoGeneration6.class);
  }

  @Test
  public void testPrimaryKeyWithAutoGeneration7() throws Exception {
    compareSchema(PrimaryKeyWithAutoGeneration7.class);
  }

  @Test
  public void testPrimaryKeyWithAutoGeneration8() throws Exception {
    compareSchema(PrimaryKeyWithAutoGeneration8.class);
  }

  private static void compareSchema(Class clazz) throws Exception {
    Assert.assertEquals(readExpectedSchema(clazz), getSchema(clazz));
  }

  private static String getSchema(Class clazz) {
    return new StandardModelToTigrisJsonSchema().toJsonSchema(clazz).toPrettyString();
  }

  private static String readExpectedSchema(Class testModel) throws Exception {
    List<String> lines;
    try (BufferedReader br =
        new BufferedReader(
            new InputStreamReader(
                SchemaGenerationTest.class.getResourceAsStream(
                    "/testdata" + "/" + testModel.getSimpleName() + ".json")))) {
      lines = new ArrayList<>();
      String line;
      while ((line = br.readLine()) != null) {
        lines.add(line);
      }
    }
    return String.join("\n", lines);
  }
}
