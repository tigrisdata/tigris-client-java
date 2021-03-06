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

package com.tigrisdata.db.client.search;

import com.tigrisdata.db.api.v1.grpc.Api;
import java.util.Objects;

/** Summary of facets in search results */
public final class FacetStats {

  private final double avg;
  private final long count;
  private final double max;
  private final double min;
  private final double sum;

  private FacetStats(double avg, long count, double max, double min, double sum) {
    this.avg = avg;
    this.count = count;
    this.max = max;
    this.min = min;
    this.sum = sum;
  }

  /**
   * Count of values in faceted field
   *
   * @return Count of values in faceted field
   */
  public long getCount() {
    return count;
  }

  /**
   * Only for numeric fields. Average of values for the field
   *
   * @return `0` or average of values for the field
   */
  public double getAvg() {
    return avg;
  }

  /**
   * Only for numeric fields. Maximum numeric value for a field
   *
   * @return `0` or maximum numeric value for a field
   */
  public double getMax() {
    return max;
  }

  /**
   * Only for numeric fields. Minimum numeric value for a field
   *
   * @return `0` or minimum numeric value for a field
   */
  public double getMin() {
    return min;
  }

  /**
   * Only for numeric fields. Sum of numeric values in the field
   *
   * @return `0` or sum of numeric values in the field
   */
  public double getSum() {
    return sum;
  }

  /**
   * Conversion utility to create {@link FacetStats} from server response
   *
   * @param resp {@link Api.FacetStats}
   * @return {@link FacetStats}
   */
  static FacetStats from(Api.FacetStats resp) {
    Objects.requireNonNull(resp);

    return new FacetStats(
        resp.getAvg(), resp.getCount(), resp.getMax(), resp.getMin(), resp.getSum());
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }

    FacetStats that = (FacetStats) o;

    if (Double.compare(that.avg, avg) != 0) {
      return false;
    }
    if (count != that.count) {
      return false;
    }
    if (Double.compare(that.max, max) != 0) {
      return false;
    }
    if (Double.compare(that.min, min) != 0) {
      return false;
    }
    return Double.compare(that.sum, sum) == 0;
  }

  @Override
  public int hashCode() {
    int result;
    long temp;
    temp = Double.doubleToLongBits(avg);
    result = (int) (temp ^ (temp >>> 32));
    result = 31 * result + (int) (count ^ (count >>> 32));
    temp = Double.doubleToLongBits(max);
    result = 31 * result + (int) (temp ^ (temp >>> 32));
    temp = Double.doubleToLongBits(min);
    result = 31 * result + (int) (temp ^ (temp >>> 32));
    temp = Double.doubleToLongBits(sum);
    result = 31 * result + (int) (temp ^ (temp >>> 32));
    return result;
  }
}
