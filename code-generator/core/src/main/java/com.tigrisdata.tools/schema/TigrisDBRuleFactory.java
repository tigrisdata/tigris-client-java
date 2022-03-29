package com.tigrisdata.tools.schema;

import com.sun.codemodel.JClassContainer;
import com.sun.codemodel.JDefinedClass;
import com.sun.codemodel.JPackage;
import com.sun.codemodel.JType;
import org.jsonschema2pojo.Annotator;
import org.jsonschema2pojo.GenerationConfig;
import org.jsonschema2pojo.SchemaStore;
import org.jsonschema2pojo.rules.Rule;
import org.jsonschema2pojo.rules.RuleFactory;
import org.jsonschema2pojo.util.ParcelableHelper;
import org.jsonschema2pojo.util.ReflectionHelper;

/** This is to customize the model generation */
public class TigrisDBRuleFactory extends RuleFactory {
  private final ReflectionHelper reflectionHelper;

  public TigrisDBRuleFactory(
      GenerationConfig generationConfig, Annotator annotator, SchemaStore schemaStore) {
    super(generationConfig, annotator, schemaStore);
    this.reflectionHelper = new ReflectionHelper(this);
  }

  @Override
  public Rule<JClassContainer, JType> getTypeRule() {
    return new TigrisDBTypeRule(this);
  }

  @Override
  public Rule<JDefinedClass, JDefinedClass> getConstructorRule() {
    return new TigrisDBConstructorRule(this, reflectionHelper);
  }

  @Override
  public Rule<JPackage, JType> getObjectRule() {
    return new TigrisDBObjectRule(this, new ParcelableHelper(), reflectionHelper);
  }
}