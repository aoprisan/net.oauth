/*
 * Copyright 2007 Sxip Identity Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.oauth.alpha;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map.Entry;
import java.io.*;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.httpclient.*;
import org.apache.commons.httpclient.methods.*;
import org.apache.commons.httpclient.params.HttpMethodParams;

import net.oauth.alpha.ConsumerConfig;
import net.oauth.alpha.token.*;
import net.oauth.alpha.signature.*;

public class Consumer {
    private ConsumerConfig config;
    private String signatureMethod;

    public Consumer() {
        config = new ConsumerConfig();
        signatureMethod = "PLAINTEXT";
    }

    public Consumer(String key, String secret) {
        config = new ConsumerConfig(key, secret);
        signatureMethod = "PLAINTEXT";
    }

    public Consumer(String key, String secret, String callbackEndpoint) {
        config = new ConsumerConfig(key, secret, callbackEndpoint);
        signatureMethod = "PLAINTEXT";
    }

    //
    // Getters and setters
    //
    public ConsumerConfig getConfig() {
        return config;
    }

    public void setConfig(ConsumerConfig config) {
        this.config = config;
    }

    public String getSignatureMethod() {
        return signatureMethod;
    }

    public void setSignatureMethod(String signatureMethod) {
        this.signatureMethod = signatureMethod;
    }

    //
    // Token request messages
    //
    public RequestToken getRequestToken(String endpoint) {
        RequestToken token = new RequestToken();

        OAuthMessage requestMessage = new OAuthMessage();
        requestMessage.setConsumerKey(config.getKey());
        requestMessage.createSignature(signatureMethod, config.getSecret());

        HttpClient client = new HttpClient();
        GetMethod method = new GetMethod(endpoint
            + "?" + requestMessage.convertToUrlParameters());

        //System.out.println("Getting request token from: " + endpoint + "?" + requestMessage.convertToUrlParameters());

        try {
            int statusCode = client.executeMethod(method);
            if (statusCode != HttpStatus.SC_OK) {
                ;
            }

            byte[] responseBody = method.getResponseBody();
            String responseString = new String(responseBody);
            //System.out.println("Consumer got responseString when requesting RequestToken..." + responseString);

            OAuthMessage responseMessage = new OAuthMessage(responseString);
            token.setToken(responseMessage.getToken());
            token.setSecret(responseMessage.getTokenSecret());
        }  catch (HttpException e) {
            ;
        } catch (IOException e) {
            ;
        } finally {
            method.releaseConnection();
        }

        return token;
    }

    public AccessToken getAccessToken(String endpoint, RequestToken requestToken) {
        if (!requestToken.getAuthorized()) {
            return null;
        }

        if (requestToken.getExchanged()) {
            return null;
        }

        AccessToken token = new AccessToken();

        OAuthMessage requestMessage = new OAuthMessage();
        requestMessage.setToken(requestToken.getToken());
        requestMessage.setCallback(config.getCallbackEndpoint());
        requestMessage.createSignature(signatureMethod, config.getSecret());

        HttpClient client = new HttpClient();
        PostMethod method = new PostMethod(endpoint);
        HashMap<String,String> requestProperties = requestMessage.convertToKeyValuePairs();

        try {
            Iterator<Entry<String,String>> iter =
                requestProperties.entrySet().iterator();
            String key = "";
            while (iter.hasNext()) {
                try {
                    key = iter.next().getKey();
                    method.addParameter(key, requestProperties.get(key));
                } catch (java.util.NoSuchElementException e) {
                    ;
                }
            }
        } catch (NullPointerException e) {
            ;
        } catch (Exception e) {
            ;
        }

        try {
            int statusCode = client.executeMethod(method);
            if (statusCode != HttpStatus.SC_OK) {
                ;
            }

            byte[] responseBody = method.getResponseBody();
            String responseString = new String(responseBody);
            //System.out.println("Consumer got responseString when requesting AccessToken..." + responseString);

            OAuthMessage responseMessage = new OAuthMessage(responseString);
            token.setToken(responseMessage.getToken());
            token.setSecret(responseMessage.getTokenSecret());

            requestToken.setExchanged(true);
        }  catch (HttpException e) {
            ;
        } catch (IOException e) {
            ;
        } finally {
            method.releaseConnection();
        }

        return token;
    }

    public RequestToken markRequestTokenAuthorized(RequestToken token) {
        token.setAuthorized(true);
        return token;
    }

    public RequestToken markRequestTokenExchanged(RequestToken token) {
        token.setExchanged(true);
        return token;
    }
}
