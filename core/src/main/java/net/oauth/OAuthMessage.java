/*
 * Copyright 2007, 2008 Netflix, Inc.
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

package net.oauth;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.oauth.http.HttpMessage;
import net.oauth.signature.OAuthSignatureMethod;

/**
 * A request or response message used in the OAuth protocol.
 * <p>
 * The parameters in this class are not percent-encoded. Methods like
 * OAuthClient.invoke and OAuthResponseMessage.completeParameters are
 * responsible for percent-encoding parameters before transmission and decoding
 * them after reception.
 * 
 * @author John Kristian
 */
public class OAuthMessage {

    public OAuthMessage(String method, String URL,
            Collection<? extends Map.Entry> parameters) {
        this.method = method;
        this.URL = URL;
        if (parameters == null) {
            this.parameters = new ArrayList<Map.Entry<String, String>>();
        } else {
            this.parameters = new ArrayList<Map.Entry<String, String>>(parameters.size());
            for (Map.Entry p : parameters) {
                this.parameters.add(new OAuth.Parameter(
                        toString(p.getKey()), toString(p.getValue())));
            }
        }
    }

    public String method;
    public String URL;

    private final List<Map.Entry<String, String>> parameters;
    private Map<String, String> parameterMap;
    private boolean parametersAreComplete = false;
    private final List<Map.Entry<String, String>> headers = new ArrayList<Map.Entry<String, String>>();
    
    public String toString() {
        return "OAuthMessage(" + method + ", " + URL + ", " + parameters + ")";
    }

    /** A caller is about to get a parameter. */
    private void beforeGetParameter() throws IOException {
        if (!parametersAreComplete) {
            completeParameters();
            parametersAreComplete = true;
        }
    }

    /**
     * Finish adding parameters; for example read an HTTP response body and
     * parse parameters from it.
     */
    protected void completeParameters() throws IOException {
    }

    public List<Map.Entry<String, String>> getParameters() throws IOException {
        beforeGetParameter();
        return Collections.unmodifiableList(parameters);
    }

    public void addParameter(String key, String value) {
        addParameter(new OAuth.Parameter(key, value));
    }

    public void addParameter(Map.Entry<String, String> parameter) {
        parameters.add(parameter);
        parameterMap = null;
    }

    public void addParameters(
            Collection<? extends Map.Entry<String, String>> parameters) {
        this.parameters.addAll(parameters);
        parameterMap = null;
    }

    public String getParameter(String name) throws IOException {
        return getParameterMap().get(name);
    }

    public String getConsumerKey() throws IOException {
        return getParameter("oauth_consumer_key");
    }

    public String getToken() throws IOException {
        return getParameter("oauth_token");
    }

    public String getSignatureMethod() throws IOException {
        return getParameter("oauth_signature_method");
    }

    public String getSignature() throws IOException {
        return getParameter("oauth_signature");
    }

    protected Map<String, String> getParameterMap() throws IOException {
        beforeGetParameter();
        if (parameterMap == null) {
            parameterMap = OAuth.newMap(parameters);
        }
        return parameterMap;
    }

    /**
     * The MIME type of the body of this message.
     * 
     * @return the MIME type, or null to indicate the type is unknown.
     */
    public String getBodyType() {
        return getHeader(HttpMessage.CONTENT_TYPE);
    }

    /**
     * The character encoding of the body of this message.
     * 
     * @return the name of an encoding, or "ISO-8859-1" if no charset has been
     *         specified.
     */
    public String getBodyEncoding() {
        return HttpMessage.DEFAULT_CHARSET;
    }

    /**
     * The value of the last HTTP header with the given name. The name is case
     * insensitive.
     * 
     * @return the value of the last header, or null to indicate that there is
     *         no such header in this message.
     */
    public final String getHeader(String name) {
        String value = null; // no such header
        for (Map.Entry<String, String> header : getHeaders()) {
            if (name.equalsIgnoreCase(header.getKey())) {
                value = header.getValue();
            }
        }
        return value;
    }

    /** All HTTP headers. */
    public final List<Map.Entry<String, String>> getHeaders() {
        return headers;
    }

    /**
     * Read the body of the HTTP request or response and convert it to a String.
     * This method isn't repeatable, since it consumes getBodyAsStream.
     * 
     * @return the body, or null to indicate there is no body.
     */
    public final String readBodyAsString() throws IOException
    {
        InputStream body = getBodyAsStream();
        if (body == null) {
            return null;
        }
        return readAll(body, getBodyEncoding());
    }

    /**
     * Get a stream from which to read the body of the HTTP request or response.
     * This is designed to support efficient streaming of a large message.
     * 
     * @return a stream from which to read the body, or null to indicate there
     *         is no body.
     */
    public InputStream getBodyAsStream() throws IOException {
        return null;
    }

    /**
     * The name of a dump entry whose value is the HTTP request.
     * 
     * @deprecated use HttpMessage.REQUEST instead
     */
    public static final String HTTP_REQUEST = HttpMessage.REQUEST;

    /**
     * The name of a dump entry whose value is the HTTP response.
     * 
     * @deprecated use HttpMessage.RESPONSE instead
     */
    public static final String HTTP_RESPONSE = HttpMessage.RESPONSE;
    
    /** Construct a verbose description of this message and its origins. */
    public Map<String, Object> getDump() throws IOException {
        Map<String, Object> into = new HashMap<String, Object>();
        dump(into);
        return into;
    }

    protected void dump(Map<String, Object> into) throws IOException {
        into.put("URL", URL);
        if (parametersAreComplete) {
            try {
                into.putAll(getParameterMap());
            } catch (Exception ignored) {
            }
        }
    }

    /**
     * Verify that the required parameter names are contained in the actual
     * collection.
     * 
     * @throws OAuthProblemException
     *                 one or more parameters are absent.
     * @throws IOException
     */
    public void requireParameters(String... names)
            throws OAuthProblemException, IOException {
        Set<String> present = getParameterMap().keySet();
        List<String> absent = new ArrayList<String>();
        for (String required : names) {
            if (!present.contains(required)) {
                absent.add(required);
            }
        }
        if (!absent.isEmpty()) {
            OAuthProblemException problem = new OAuthProblemException(
                    "parameter_absent");
            problem.setParameter("oauth_parameters_absent", OAuth
                    .percentEncode(absent));
            throw problem;
        }
    }

    /**
     * Add some of the parameters needed to request access to a protected
     * resource, if they aren't already in the message.
     * 
     * @throws IOException
     * @throws URISyntaxException
     */
    public void addRequiredParameters(OAuthAccessor accessor)
            throws OAuthException, IOException, URISyntaxException {
        final Map<String, String> pMap = OAuth.newMap(parameters);
        if (pMap.get("oauth_token") == null && accessor.accessToken != null) {
            addParameter("oauth_token", accessor.accessToken);
        }
        final OAuthConsumer consumer = accessor.consumer;
        if (pMap.get("oauth_consumer_key") == null) {
            addParameter("oauth_consumer_key", consumer.consumerKey);
        }
        String signatureMethod = pMap.get("oauth_signature_method");
        if (signatureMethod == null) {
            signatureMethod = (String) consumer
                    .getProperty("oauth_signature_method");
            if (signatureMethod == null) {
                signatureMethod = "HMAC-SHA1";
            }
            addParameter("oauth_signature_method", signatureMethod);
        }
        if (pMap.get("oauth_timestamp") == null) {
            addParameter("oauth_timestamp", (System.currentTimeMillis() / 1000)
                    + "");
        }
        if (pMap.get("oauth_nonce") == null) {
            addParameter("oauth_nonce", System.nanoTime() + "");
        }
        if (pMap.get("oauth_version") == null) {
        	addParameter("oauth_version", "1.0");
        }
        this.sign(accessor);
    }

    /**
     * Add a signature to the message.
     * 
     * @throws URISyntaxException
     */
    public void sign(OAuthAccessor accessor) throws IOException,
            OAuthException, URISyntaxException {
        OAuthSignatureMethod.newSigner(this, accessor).sign(this);
    }

    /**
     * Check that the message is valid.
     * 
     * @throws IOException
     * @throws URISyntaxException
     * 
     * @throws OAuthProblemException
     *                 the message is invalid
     */
    public void validateMessage(OAuthAccessor accessor, OAuthValidator validator)
            throws OAuthException, IOException, URISyntaxException {
        validator.validateMessage(this, accessor);
    }

    /**
     * Check that the message has a valid signature.
     * 
     * @throws IOException
     * @throws URISyntaxException
     * 
     * @throws OAuthProblemException
     *                 the signature is invalid
     * @deprecated use {@link OAuthMessage#validateMessage} instead.
     */
    public void validateSignature(OAuthAccessor accessor)
            throws OAuthException, IOException, URISyntaxException {
        OAuthSignatureMethod.newSigner(this, accessor).validate(this);
    }

    /**
     * Construct a WWW-Authenticate or Authentication header value, containing
     * the given realm plus all the parameters whose names begin with "oauth_".
     */
    public String getAuthorizationHeader(String realm) throws IOException {
        StringBuilder into = new StringBuilder(AUTH_SCHEME);
        into.append(" realm=\"").append(OAuth.percentEncode(realm)).append('"');
        beforeGetParameter();
        if (parameters != null) {
            for (Map.Entry parameter : parameters) {
                String name = toString(parameter.getKey());
                if (name.startsWith("oauth_")) {
                    into.append(", ");
                    into.append(OAuth.percentEncode(name)).append("=\"")
                            .append(
                                    OAuth.percentEncode(toString(parameter
                                            .getValue()))).append('"');
                }
            }
        }
        return into.toString();
    }

    /** Read all the data from the given stream and convert it to a String. */
    public static String readAll(InputStream from, String encoding) throws IOException
    {
        StringBuilder into = new StringBuilder();
        if (from != null) {
            try {
                Reader r = new InputStreamReader(from, encoding);
                char[] s = new char[512];
                for (int n; 0 < (n = r.read(s));) {
                    into.append(s, 0, n);
                }
            } finally {
                from.close();
            }
        }
        return into.toString();
    }

    /**
     * Parse the parameters from an OAuth Authorization or WWW-Authenticate
     * header. The realm is included as a parameter. If the given header doesn't
     * start with "OAuth ", return an empty list.
     */
    public static List<OAuth.Parameter> decodeAuthorization(String authorization) {
        List<OAuth.Parameter> into = new ArrayList<OAuth.Parameter>();
        if (authorization != null) {
            Matcher m = AUTHORIZATION.matcher(authorization);
            if (m.matches()) {
                if (AUTH_SCHEME.equalsIgnoreCase(m.group(1))) {
                    for (String nvp : m.group(2).split("\\s*,\\s*")) {
                        m = NVP.matcher(nvp);
                        if (m.matches()) {
                            String name = OAuth.decodePercent(m.group(1));
                            String value = OAuth.decodePercent(m.group(2));
                            into.add(new OAuth.Parameter(name, value));
                        }
                    }
                }
            }
        }
        return into;
    }

    public static final String AUTH_SCHEME = "OAuth";

    /** @deprecated use HttpMessage.CONTENT_TYPE instead */
    public static final String CONTENT_TYPE = HttpMessage.CONTENT_TYPE;

    public static final String GET = "GET";
    public static final String POST = "POST";
    public static final String PUT = "PUT";
    public static final String DELETE = "DELETE";

    private static final Pattern AUTHORIZATION = Pattern.compile("\\s*(\\w*)\\s+(.*)");
    private static final Pattern NVP = Pattern.compile("(\\S*)\\s*\\=\\s*\"([^\"]*)\"");

    private static final String toString(Object from) {
        return (from == null) ? null : from.toString();
    }

}
