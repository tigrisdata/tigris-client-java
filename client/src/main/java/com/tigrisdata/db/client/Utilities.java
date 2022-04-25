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

import com.google.common.base.CaseFormat;
import com.google.common.reflect.ClassPath;
import com.google.common.util.concurrent.FutureCallback;
import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.ListenableFuture;
import com.tigrisdata.db.annotation.TigrisCollection;
import com.tigrisdata.db.client.error.TigrisException;
import com.tigrisdata.db.type.TigrisCollectionType;
import org.atteo.evo.inflector.English;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.function.BiConsumer;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Collectors;

final class Utilities {
  private Utilities() {}

  private static final Logger log = LoggerFactory.getLogger(Utilities.class);

  /**
   * Scans the classpath for the given packages and searches for all the top level classes that are
   * of type {@link TigrisCollectionType} and optionally filters them using user supplied filter.
   *
   * @param packagesToScan packages to scan
   * @param filter filter to select classes from scanned classes
   * @return tigris db collection model classes
   */
  static Class<? extends TigrisCollectionType>[] scanTigrisDBCollectionModels(
      String[] packagesToScan, Optional<Predicate<Class<? extends TigrisCollectionType>>> filter) {
    Set<Class<? extends TigrisCollectionType>> scannedClasses = new HashSet<>();
    for (String packageToScan : packagesToScan) {
      log.debug("scanning package {}", packageToScan);
      try {
        Set<Class<? extends TigrisCollectionType>> scannedClassesFromThisPackage =
            ClassPath.from(ClassLoader.getSystemClassLoader())
                .getTopLevelClassesRecursive(packageToScan).stream()
                .map(ClassPath.ClassInfo::load)
                .filter(clazz -> TigrisCollectionType.class.isAssignableFrom(clazz))
                .map(clazz -> (Class<? extends TigrisCollectionType>) clazz)
                .filter(
                    clazz -> filter.map(classPredicate -> classPredicate.test(clazz)).orElse(true))
                .collect(Collectors.toSet());
        log.debug("found {}", scannedClasses);
        scannedClasses.addAll(scannedClassesFromThisPackage);
      } catch (Exception ex) {
        log.warn("failed to scan " + packageToScan, ex);
      }
    }

    Class<? extends TigrisCollectionType> result[] = new Class[scannedClasses.size()];
    int i = 0;
    for (Class<? extends TigrisCollectionType> scannedClass : scannedClasses) {
      result[i] = scannedClass;
      i++;
    }
    log.debug("Total classes found={}, all classes = {}", result.length, Arrays.toString(result));
    return result;
  }

  static String getCollectionName(Class<? extends TigrisCollectionType> clazz) {
    TigrisCollection tigrisCollection = clazz.getAnnotation(TigrisCollection.class);
    if (tigrisCollection != null) {
      return tigrisCollection.value();
    }
    return CaseFormat.UPPER_CAMEL.to(
        CaseFormat.LOWER_UNDERSCORE, English.plural(clazz.getSimpleName()));
  }

  /**
   * Converts from {@link Iterator} of Type F to {@link Iterator} of type T
   *
   * @param iterator source iterator
   * @param converter function that converts F to T type
   * @param <F> source type
   * @param <T> destination type
   * @return an instance of {@link Iterator} of type T
   */
  static <F, T> Iterator<T> transformIterator(Iterator<F> iterator, Function<F, T> converter) {
    return new ConvertedIterator<>(iterator, converter);
  }

  /**
   * Converts {@link ListenableFuture} of type F to {@link CompletableFuture} of type T
   *
   * @param listenableFuture source listenable future
   * @param converter function that converts type F to type T
   * @param executor executor to run callback that transforms Future when source Future is complete
   * @param <F> from type
   * @param <T> to type
   * @return an instance of {@link CompletableFuture}
   */
  static <F, T> CompletableFuture<T> transformFuture(
      ListenableFuture<F> listenableFuture,
      Function<F, T> converter,
      Executor executor,
      String errorMessage) {
    return transformFuture(listenableFuture, converter, executor, errorMessage, Optional.empty());
  }
  /**
   * Converts {@link ListenableFuture} of type F to {@link CompletableFuture} of type T
   *
   * @param listenableFuture source listenable future
   * @param converter function that converts type F to type T
   * @param executor executor to run callback that transforms Future when source Future is complete
   * @param exceptionHandler handles exception
   * @param <F> from type
   * @param <T> to type
   * @return an instance of {@link CompletableFuture}
   */
  static <F, T> CompletableFuture<T> transformFuture(
      ListenableFuture<F> listenableFuture,
      Function<F, T> converter,
      Executor executor,
      String errorMessage,
      Optional<BiConsumer<CompletableFuture<T>, Throwable>> exceptionHandler) {
    CompletableFuture<T> result = new CompletableFuture<>();
    Futures.addCallback(
        listenableFuture,
        new FutureCallback<F>() {
          @Override
          public void onSuccess(F f) {
            result.complete(converter.apply(f));
          }

          @Override
          public void onFailure(Throwable throwable) {
            if (exceptionHandler.isPresent()) {
              exceptionHandler.get().accept(result, throwable);
            } else {
              result.completeExceptionally(new TigrisException(errorMessage, throwable));
            }
          }
        },
        executor);
    return result;
  }

  static class ConvertedIterator<F, T> implements Iterator<T> {

    private final Iterator<F> sourceIterator;
    private final Function<F, T> converter;

    public ConvertedIterator(Iterator<F> sourceIterator, Function<F, T> converter) {
      this.sourceIterator = sourceIterator;
      this.converter = converter;
    }

    @Override
    public boolean hasNext() {
      return sourceIterator.hasNext();
    }

    @Override
    public T next() {
      return converter.apply(sourceIterator.next());
    }
  }
}
