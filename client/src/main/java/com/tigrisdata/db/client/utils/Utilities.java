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
package com.tigrisdata.db.client.utils;

import com.google.common.util.concurrent.FutureCallback;
import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.ListenableFuture;
import com.tigrisdata.db.client.error.TigrisDBException;

import java.util.Iterator;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.function.Function;

public final class Utilities {
  private Utilities() {}

  // TODO update this once server sends the message back
  public static final String INSERT_SUCCESS_RESPONSE = "inserted";
  public static final String DELETE_SUCCESS_RESPONSE = "deleted";

  /**
   * Converts from {@link Iterator} of Type F to {@link Iterator} of type T
   *
   * @param iterator source iterator
   * @param converter function that converts F to T type
   * @param <F> source type
   * @param <T> destination type
   * @return an instance of {@link Iterator} of type T
   */
  public static <F, T> Iterator<T> transformIterator(
      Iterator<F> iterator, Function<F, T> converter) {
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
  public static <F, T> CompletableFuture<T> transformFuture(
      ListenableFuture<F> listenableFuture,
      Function<F, T> converter,
      Executor executor,
      String errorMessage) {
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
            result.completeExceptionally(new TigrisDBException(errorMessage, throwable));
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
