/**
 * Licensed to The Apereo Foundation under one or more contributor license
 * agreements. See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
 *
 *
 * The Apereo Foundation licenses this file to you under the Educational
 * Community License, Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of the License
 * at:
 *
 *   http://opensource.org/licenses/ecl2.txt
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations under
 * the License.
 *
 */
package org.opencastproject.security.urlsigning.provider.impl;


import org.opencastproject.security.urlsigning.WowzaResourceStrategyImpl;
import org.opencastproject.security.urlsigning.exception.UrlSigningException;
import org.opencastproject.urlsigning.common.Policy;
import org.opencastproject.urlsigning.common.ResourceStrategy;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;

public class WowzaUrlSigningProvider extends AbstractUrlSigningProvider {
  private static final Logger logger = LoggerFactory.getLogger(WowzaUrlSigningProvider.class);
  /** The Wowza resource strategy to use to convert from the base url to a resource url. */
  private ResourceStrategy resourceStrategy = new WowzaResourceStrategyImpl();

  @Override
  public Logger getLogger() {
    return logger;
  }

  @Override
  public ResourceStrategy getResourceStrategy() {
    return resourceStrategy;
  }

  @Override
  public String toString() {
    return "Wowza URL Signing Provider";
  }

  @Override
  public String sign(Policy policy) throws UrlSigningException {
    if (!accepts(policy.getBaseUrl())) {
      throw UrlSigningException.urlNotSupported();
    }
    // Get the key that matches this URI since there must be one that matches as the base url has been accepted.
    AbstractUrlSigningProvider.KeyEntry keyEntry = getKeyEntry(policy.getBaseUrl());

    policy.setResourceStrategy(getResourceStrategy());

    try {
      URI uri = new URI(policy.getBaseUrl());
      List<NameValuePair> queryStringParameters = new ArrayList<>();
      if (uri.getQuery() != null) {
        queryStringParameters = URLEncodedUtils.parse(new URI(policy.getBaseUrl()).getQuery(), StandardCharsets.UTF_8);
      }
      queryStringParameters.addAll(URLEncodedUtils.parse(
              addSignutureToRequest(policy, keyEntry.getId(), keyEntry.getKey()), //ResourceRequestUtil.policyToResourceRequestQueryString(policy, keyEntry.getId(), keyEntry.getKey()),
              StandardCharsets.UTF_8));
      return new URI(uri.getScheme(), null, uri.getHost(), uri.getPort(), uri.getPath(),
              addSignutureToRequest(policy, keyEntry.getId(), keyEntry.getKey()), null).toString();
    } catch (Exception e) {
      getLogger().error("Unable to create signed URL because {}", ExceptionUtils.getStackTrace(e));
      throw new UrlSigningException(e);
    }
  }

  @SuppressWarnings("unchecked")
  private String addSignutureToRequest(Policy policy, String encryptionKeyId, String encryptionKey) throws Exception  {
    //List<NameValuePair> queryStringParameters = new ArrayList<NameValuePair>();
    getLogger().error("DEBUG: " + Base64.getEncoder().encodeToString(policy.getResource().getBytes(StandardCharsets.UTF_8)));

    final String startTime;
    final String endTime = Long.toString(policy.getValidUntil().getMillis() / 1000);

    if (policy.getValidFrom().isPresent()) {
        startTime = Long.toString(policy.getValidFrom().get().getMillis() / 1000);
    } else {
        OffsetDateTime utc = OffsetDateTime.now(ZoneOffset.UTC);
        startTime = Long.toString(utc.toEpochSecond());
    }

    String queryStringParameters = new String();

    queryStringParameters +=  encryptionKeyId + "endtime=" + endTime;
    //queryStringParameters.add(new BasicNameValuePair(encryptionKeyId + "endtime", endTime));

    queryStringParameters += "&" + encryptionKeyId + "starttime=" + startTime;
    //queryStringParameters.add(new BasicNameValuePair(encryptionKeyId + "starttime", startTime));
    //}

    queryStringParameters += "&" + encryptionKeyId + "hash=" + generateHash(policy, encryptionKeyId, encryptionKey, startTime, endTime);
    //queryStringParameters.add(new BasicNameValuePair(encryptionKeyId + "hash", generateHash(policy, encryptionKeyId, encryptionKey, startTime, endTime)));

    return queryStringParameters;//URLEncodedUtils.format(queryStringParameters, StandardCharsets.US_ASCII);
  }

  private String generateHash(Policy policy, String encryptionKeyId, String encryptionKey, String startTime, String endTime) throws Exception {
    String urlToHash = policy.getResource();

    urlToHash += "?" + encryptionKey;

    SortedMap<String, String> arguments = new TreeMap<String, String>();

    arguments.put(encryptionKeyId + "endtime", endTime);
    arguments.put(encryptionKeyId + "starttime", startTime);

    for (Map.Entry<String,String> entry : arguments.entrySet()) {
        String value = entry.getValue();
        String key = entry.getKey();

        urlToHash += "&" + key + "=" + value;
    }

    getLogger().error(urlToHash);

    MessageDigest md = MessageDigest.getInstance("SHA-256");

    byte[] messageDigest = md.digest(urlToHash.getBytes());
    String base64Hash = Base64.getEncoder().encodeToString(messageDigest);

    base64Hash = base64Hash.replaceAll("\\+", "-");
    base64Hash = base64Hash.replaceAll("/", "_");

    return base64Hash;
  }
}
