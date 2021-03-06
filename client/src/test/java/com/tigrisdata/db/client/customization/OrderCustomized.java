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
package com.tigrisdata.db.client.customization;

import com.tigrisdata.db.annotation.TigrisField;
import com.tigrisdata.db.type.AutoGeneratedFields;
import com.tigrisdata.db.type.TigrisCollectionType;

import java.util.Objects;
import java.util.UUID;

public class OrderCustomized implements TigrisCollectionType {
  private long buyerId;
  private long sellerId;
  private double tradePrice;

  @TigrisField(autoGeneratedFieldMapping = AutoGeneratedFields.ID)
  private UUID orderId;

  public UUID getOrderId() {
    return orderId;
  }

  public void setOrderId(UUID orderId) {
    this.orderId = orderId;
  }

  public long getBuyerId() {
    return buyerId;
  }

  public void setBuyerId(long buyerId) {
    this.buyerId = buyerId;
  }

  public long getSellerId() {
    return sellerId;
  }

  public void setSellerId(long sellerId) {
    this.sellerId = sellerId;
  }

  public double getTradePrice() {
    return tradePrice;
  }

  public void setTradePrice(double tradePrice) {
    this.tradePrice = tradePrice;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    OrderCustomized that = (OrderCustomized) o;
    return buyerId == that.buyerId
        && sellerId == that.sellerId
        && Double.compare(that.tradePrice, tradePrice) == 0
        && Objects.equals(orderId, that.orderId);
  }

  @Override
  public int hashCode() {
    return Objects.hash(buyerId, sellerId, tradePrice, orderId);
  }
}
