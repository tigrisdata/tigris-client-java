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

import com.google.api.client.auth.oauth2.RefreshTokenRequest;
import com.google.api.client.auth.oauth2.TokenResponse;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.gson.GsonFactory;
import com.tigrisdata.db.client.config.TigrisConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

class OAuth2TokenService implements TokenService {
  private final TigrisConfiguration.OAuth2Config oAuth2Config;
  private final AtomicReference<String> accessToken;
  private final AtomicLong lastRefreshed;
  private final AtomicLong nextRefreshTime;
  private final Object lock;

  private static final Logger log = LoggerFactory.getLogger(OAuth2TokenService.class);
  private static final String CLIENT_ID = "client_id";

  OAuth2TokenService(TigrisConfiguration.OAuth2Config oAuth2Config) {
    this.oAuth2Config = oAuth2Config;
    this.accessToken = new AtomicReference<>("");
    this.lock = new Object();
    this.lastRefreshed = new AtomicLong(0L);
    this.nextRefreshTime = new AtomicLong(0L);
  }

  @Override
  public String getAccessToken() {
    if (shouldRefresh()) {
      // refresh
      refresh();
    }
    return accessToken.get();
  }

  private boolean shouldRefresh() {
    return (accessToken.get() == null || accessToken.get().isEmpty())
        || (nextRefreshTime.get() != 0L && nextRefreshTime.get() <= System.currentTimeMillis());
  }

  private void refresh() {
    synchronized (lock) {
      // if it was never refreshed OR nextRefreshTime has arrived
      if (shouldRefresh()) {
        try {
          TokenResponse response =
              new RefreshTokenRequest(
                      new NetHttpTransport(),
                      new GsonFactory(),
                      new GenericUrl(oAuth2Config.getTokenURL()),
                      oAuth2Config.getRefreshToken())
                  .set(CLIENT_ID, oAuth2Config.getClientId())
                  .execute();
          accessToken.set(response.getAccessToken());
          lastRefreshed.set(System.currentTimeMillis());
          // refresh before 1minute of expiry
          nextRefreshTime.set(
              (System.currentTimeMillis() + response.getExpiresInSeconds() * 1000L)
                  - TimeUnit.MINUTES.toMillis(1));
        } catch (IOException ioException) {
          log.error("Failed to refresh access token", ioException);
        }
      }
    }
  }
}
