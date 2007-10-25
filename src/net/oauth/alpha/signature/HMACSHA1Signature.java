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

package net.oauth.alpha.signature;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import net.oauth.alpha.OAuthParameterEncoder;
import net.oauth.alpha.OAuthParameterDecoder;

public class HMACSHA1Signature implements OAuthSignature {
    private String method;
    private String message;
    private String key;
    private String signature;

    public HMACSHA1Signature() {
        method = "HMAC-SHA1";
        message = "";
        signature = "";
    }

    public String getMethod() {
        return method;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = key;
    }

    public String getSignature() {
        try {
            SecretKey secKey = new SecretKeySpec(key.getBytes("UTF-8"), "HmacSHA1");
            Mac m = Mac.getInstance("HmacSHA1");
            m.init(secKey);
            m.update(message.getBytes("UTF-8"));
            byte[] mac = m.doFinal();
            signature = new String(mac);
        } catch (java.io.UnsupportedEncodingException e) {
            ;
        } catch (java.security.NoSuchAlgorithmException e) {
            ;
        } catch (java.security.InvalidKeyException e) {
            ;
        } catch (Exception e) {
            ;
        }

        return signature;
    }
}
