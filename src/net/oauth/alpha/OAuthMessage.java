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

import java.util.Enumeration;
import java.util.HashMap;
import java.util.TreeMap;
import java.util.Iterator;
import java.util.Map.Entry;
import java.util.Date;
import java.util.Random;
import javax.servlet.http.HttpServletRequest;
import java.net.URLEncoder;
import java.net.URLDecoder;

import net.oauth.alpha.Nonce;
import net.oauth.alpha.OAuthParameterEncoder;
import net.oauth.alpha.OAuthParameterDecoder;
import net.oauth.alpha.signature.*;

public class OAuthMessage {
    private String requestMethod;
    private String requestURL;
    private String consumerKey;
    private String version;
    private String signatureMethod;
    private String signature;
    private String timestamp;
    private String nonce;
    private String token;
    private String tokenSecret;
    private String callback;
    private TreeMap<String,String> requestParameters;

    public OAuthMessage() {
        requestMethod = "GET";
        version = "1.0";
        signatureMethod = "PLAINTEXT";

        Date d = new Date();
        timestamp = Double.toString(Math.floor(d.getTime()/1000));

        Nonce n = new Nonce();
        nonce = n.getNonce();
    }

    public OAuthMessage(HttpServletRequest request) {
        requestMethod = request.getMethod();
        requestURL = request.getRequestURI();

        // Check the authorization header first
        String authorizationHeader = "";
        HashMap<String,String> authorizationParams = new HashMap<String,String>();
        if (!"".equals(request.getHeader("Authorization"))
                && request.getHeader("Authorization").startsWith("OAuth ")) {
            // OAuth realm="...", oauth_consumer_key="..." ...
            authorizationHeader = request.getHeader("Authorization");
            authorizationHeader.substring(6); //"OAuth ".length()
            String[] headerParams = authorizationHeader.split(",");
            for (int i = 0; i < headerParams.length; i++) {
                headerParams[i] = headerParams[i].trim();
                String[] paramKeyAndValue = headerParams[i].split("=");
                authorizationParams.put(paramKeyAndValue[0],
                    paramKeyAndValue[1].substring(1, paramKeyAndValue[1].length() -1));
            }

            consumerKey = authorizationParams.get("oauth_consumer_key");
            version = authorizationParams.get("oauth_version");
            signatureMethod = authorizationParams.get("oauth_signature_method");
            signature = authorizationParams.get("oauth_signature");
            timestamp = authorizationParams.get("oauth_timestamp");
            nonce = authorizationParams.get("oauth_nonce");
            token = authorizationParams.get("oauth_token");
            tokenSecret = authorizationParams.get("oauth_token_secret");
            callback = authorizationParams.get("oauth_callback");
        } /*else {
            // Get rest of values from post body or query string
            consumerKey = request.getParameter("oauth_consumer_key");
            version = request.getParameter("oauth_version");
            signatureMethod = request.getParameter("oauth_signature_method");
            signature = request.getParameter("oauth_signature");
            timestamp = request.getParameter("oauth_timestamp");
            nonce = request.getParameter("oauth_nonce");
            token = request.getParameter("oauth_token");
            tokenSecret = request.getParameter("oauth_token_secret");
            callback = request.getParameter("oauth_callback");
        }
        */

        // Get rest of values from post body or query string
        String param = "";
        for (Enumeration<String> e = request.getParameterNames(); e.hasMoreElements();) {
            param = e.nextElement();

            // Check for known oauth keys
            if ("oauth_consumer_key".equals(param) && consumerKey == null) {
                consumerKey = request.getParameter(param);
            } else if ("oauth_version".equals(param) && version == null) {
                version = request.getParameter(param);
            } else if ("oauth_signature_method".equals(param) && signatureMethod == null) {
                signatureMethod = request.getParameter(param);
            } else if ("oauth_signature".equals(param) && signature == null) {
                signature = request.getParameter(param);
            } else if ("oauth_timestamp".equals(param) && timestamp == null) {
                timestamp = request.getParameter(param);
            } else if ("oauth_nonce".equals(param) && nonce == null) {
                nonce = request.getParameter(param);
            } else if ("oauth_token".equals(param) && token == null) {
                token = request.getParameter(param);
            } else if ("oauth_token_secret".equals(param) && tokenSecret == null) {
                tokenSecret = request.getParameter(param);
            } else if ("oauth_callback".equals(param) && callback == null) {
                callback = request.getParameter(param);
            }

            // Put all the parameters into requestParameters
            if (!"oauth_signature".equals(param)) {
                requestParameters.put(param, request.getParameter(param));
            }
        }
    }

    public OAuthMessage(String response) {
        parseResponseString(response);
    }

    //
    // Standard getters and setters
    //
    public String getRequestMethod() {
        return requestMethod;
    }

    public void setRequestMethod(String requestMethod) {
        this.requestMethod = requestMethod;
    }

    public String getRequestURL() {
        return requestURL;
    }

    public void setRequestURL(String requestURL) {
        this.requestURL = requestURL;
    }

    public String getConsumerKey() {
        return consumerKey;
    }

    public void setConsumerKey(String consumerKey) {
        this.consumerKey = consumerKey;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public String getSignatureMethod() {
        return signatureMethod;
    }

    public void setSignatureMethod(String signatureMethod) {
        this.signatureMethod = signatureMethod;
    }

    public String getSignature() {
        return signature;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }

    public String getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(String timestamp) {
        this.timestamp = timestamp;
    }

    public String getNonce() {
        return nonce;
    }

    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public String getTokenSecret() {
        return tokenSecret;
    }

    public void setTokenSecret(String tokenSecret) {
        this.tokenSecret = tokenSecret;
    }

    public String getCallback() {
        return callback;
    }

    public void setCallback(String callbak) {
        this.callback = callback;
    }

    public TreeMap<String,String> getrequestParameters() {
        return requestParameters;
    }

    public void setAttitionalProperties(TreeMap<String,String> requestParameters) {
        this.requestParameters = requestParameters;
    }

    //
    // Other Methods
    //
    public String getAdditionalProperty(String key) {
        return requestParameters.get(key);
    }

    public void setAdditionalProperty(String key, String value) {
        if (!"oauth_signature".equals(key)) {
            requestParameters.put(key, value);
        }
    }

    public void parseResponseString(String response) {
        if (response.indexOf("&") != -1) {
            String[] nameValuePairs = response.split("&");
            for (int i = 0; i < nameValuePairs.length; i++) {
                String[] singleNameValuePair = nameValuePairs[i].split("=", 2);
                // TODO: decode values with URLDecoder

                // Check for known oauth keys
                if ("oauth_consumer_key".equals(singleNameValuePair[0])) {
                    consumerKey = singleNameValuePair[1];
                } else if ("oauth_version".equals(singleNameValuePair[0])) {
                    version = singleNameValuePair[1];
                } else if ("oauth_signature_method".equals(singleNameValuePair[0])) {
                    signatureMethod = singleNameValuePair[1];
                } else if ("oauth_signature".equals(singleNameValuePair[0])) {
                    signature = singleNameValuePair[1];
                } else if ("oauth_timestamp".equals(singleNameValuePair[0])) {
                    timestamp = singleNameValuePair[1];
                } else if ("oauth_nonce".equals(singleNameValuePair[0])) {
                    nonce = singleNameValuePair[1];
                } else if ("oauth_token".equals(singleNameValuePair[0])) {
                    token = singleNameValuePair[1];
                } else if ("oauth_token_secret".equals(singleNameValuePair[0])) {
                    tokenSecret = singleNameValuePair[1];
                } else if ("oauth_callback".equals(singleNameValuePair[0])) {
                    callback = singleNameValuePair[1];
                }

                if (!"oauth_signature".equals(singleNameValuePair[0])) {
                    requestParameters.put(singleNameValuePair[0], singleNameValuePair[1]);
                }
            }
        }
    }

    public String normalizeRequestParameters() {
        String normalizedRequestParameters = "";

        try {
            Iterator<Entry<String,String>> iter =
                requestParameters.entrySet().iterator();
            String key = "";
            while (iter.hasNext()) {
                try {
                    key = iter.next().getKey();
                    if (!"".equals(normalizedRequestParameters)) {
                        normalizedRequestParameters += "&";
                    }
                    normalizedRequestParameters += key + "="
                        + requestParameters.get(key);
                } catch (java.util.NoSuchElementException e) {
                    ;
                }
            }
        } catch (NullPointerException e) {
            ;
        } catch (Exception e) {
            ;
        }

        return normalizedRequestParameters;
    }

    public String signatureBaseString(String consumerSecret) {
        String signatureBaseString = "";
        OAuthParameterEncoder encoder = new OAuthParameterEncoder();

        signatureBaseString += encoder.encode(requestMethod);
        signatureBaseString += "&" + encoder.encode(requestURL);
        signatureBaseString += "&" + encoder.encode(this.normalizeRequestParameters());
        signatureBaseString += "&" + encoder.encode(consumerSecret);
        if (tokenSecret != null) {
            signatureBaseString += "&" + encoder.encode(tokenSecret);
        } else {
            signatureBaseString += "&";
        }

        return signatureBaseString;
    }

    public String concatConsumerAndTokenSecrets(String consumerSecret, String tokenSecret) {
        OAuthParameterEncoder encoder = new OAuthParameterEncoder();
        return encoder.encode(consumerSecret)
            + "&" + encoder.encode(tokenSecret);
    }

    public void createSignature() {
        if (!"".equals(signatureMethod)) {
            createSignature(signatureMethod, "");
        }
    }

    public void createSignature(String signatureMethod, String consumerSecret) {
        this.signatureMethod = signatureMethod;
        String signatureClassName = "";
        if ("PLAINTEXT".equals(signatureMethod)) {
            signatureClassName = "net.oauth.alpha.signature.PLAINTEXTSignature";
        } else if ("HMAC-SHA1".equals(signatureMethod)) {
            signatureClassName = "net.oauth.alpha.signature.HMACSHA1Signature";
        } else if ("RSA-SHA1".equals(signatureMethod)) {
            signatureClassName = "net.oauth.alpha.signature.RSASHA1Signature";
        }

        if (!"".equals(signatureClassName)) {
            try {
                createSignature((OAuthSignature) Class.forName(signatureClassName).newInstance(),
                    consumerSecret);
            } catch (java.lang.InstantiationException e) {
                ;
            } catch (java.lang.ClassNotFoundException e) {
                ;
            } catch (Exception e) {
                ;
            }
        }
    }

    public void createSignature(OAuthSignature sigGenerator, String consumerSecret) {
        OAuthParameterEncoder encoder = new OAuthParameterEncoder();

        signatureMethod = sigGenerator.getMethod();
        if (!"PLAINTEXT".equals(signatureMethod)) {
            sigGenerator.setMessage(this.signatureBaseString(consumerSecret));
            sigGenerator.setKey(concatConsumerAndTokenSecrets(consumerSecret, tokenSecret));
        } else {
            sigGenerator.setMessage(consumerSecret);
            sigGenerator.setKey(tokenSecret);
        }
        signature = sigGenerator.getSignature();
    }

    public String convertToUrlParameters() {
        String encodedMessage = "";
        encodedMessage += "oauth_consumer_key=" + consumerKey;
        encodedMessage += "&oauth_version=" + version;

        if (!"".equals(consumerKey)) {
            encodedMessage += "oauth_consumer_key=" + consumerKey;
        }
        if (!"".equals(version)) {
            encodedMessage += "&oauth_version=" + version;
        }
        if (!"".equals(signatureMethod)) {
            encodedMessage += "&oauth_signature_method=" + signatureMethod;
        }
        if (!"".equals(signature)) {
            encodedMessage += "&oauth_signature=" + signature;
        }
        if (!"".equals(timestamp)) {
            encodedMessage += "&oauth_timestamp=" + timestamp;
        }
        if (!"".equals(nonce)) {
            encodedMessage += "&oauth_nonce=" + nonce;
        }
        if (!"".equals(token)) {
            encodedMessage += "&oauth_token=" + token;
        }
        if (!"".equals(tokenSecret)) {
            encodedMessage += "&oauth_token_secret=" + tokenSecret;
        }
        if (!"".equals(callback)) {
            encodedMessage += "&oauth_callback=" + callback;
        }

        try {
            Iterator<Entry<String,String>> iter =
                requestParameters.entrySet().iterator();
            String key = "";
            while (iter.hasNext()) {
                try {
                    key = iter.next().getKey();
                    if (key.indexOf("oauth_") == -1) {
                        encodedMessage += "&" + key + "="
                            + requestParameters.get(key);
                    }
                } catch (java.util.NoSuchElementException e) {
                    ;
                }
            }
        } catch (NullPointerException e) {
            ;
        } catch (Exception e) {
            ;
        }

        return encodedMessage;
    }

    public HashMap<String,String> convertToKeyValuePairs() {
        HashMap<String,String> keyValuePairs = new HashMap();

        if (!"".equals(consumerKey)) {
            keyValuePairs.put("oauth_consumer_key", consumerKey);
        }
        if (!"".equals(version)) {
            keyValuePairs.put("oauth_version", version);
        }
        if (!"".equals(signatureMethod)) {
            keyValuePairs.put("oauth_signature_method", signatureMethod);
        }
        if (!"".equals(signature)) {
            keyValuePairs.put("oauth_signature", signature);
        }
        if (!"".equals(timestamp)) {
            keyValuePairs.put("oauth_timestamp", timestamp);
        }
        if (!"".equals(nonce)) {
            keyValuePairs.put("oauth_nonce", nonce);
        }
        if (!"".equals(token)) {
            keyValuePairs.put("oauth_token", token);
        }
        if (!"".equals(tokenSecret)) {
            keyValuePairs.put("oauth_token_secret", tokenSecret);
        }
        if (!"".equals(callback)) {
            keyValuePairs.put("oauth_callback", callback);
        }

        try {
            Iterator<Entry<String,String>> iter =
                requestParameters.entrySet().iterator();
            String key = "";
            while (iter.hasNext()) {
                try {
                    key = iter.next().getKey();
                    if (key.indexOf("oauth_") == -1) {
                        keyValuePairs.put(key, requestParameters.get(key));
                    }
                } catch (java.util.NoSuchElementException e) {
                    ;
                }
            }
        } catch (NullPointerException e) {
            ;
        } catch (Exception e) {
            ;
        }

        return keyValuePairs;
    }
}
