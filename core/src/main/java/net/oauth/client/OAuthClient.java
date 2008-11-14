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

package net.oauth.client;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import net.oauth.OAuth;
import net.oauth.OAuthAccessor;
import net.oauth.OAuthConsumer;
import net.oauth.OAuthException;
import net.oauth.OAuthMessage;
import net.oauth.OAuthProblemException;
import net.oauth.http.HttpMessage;
import net.oauth.http.HttpMessageDecoder;
import net.oauth.http.HttpResponseMessage;

/**
 * Methods for an OAuth consumer to request tokens from a service provider.
 * <p>
 * This class can also be used to request access to protected resources, in some
 * cases. But not in all cases. For example, this class can't handle arbitrary
 * HTTP headers.
 * <p>
 * Methods of this class return a response as an OAuthMessage, from which you
 * can get a body or parameters but not both. Calling a getParameter method will
 * read and close the body (like readBodyAsString), so you can't read it later.
 * If you read or close the body first, then getParameter can't read it. The
 * response headers should tell you whether the response contains encoded
 * parameters, that is whether you should call getParameter or not.
 * <p>
 * Methods of this class don't follow redirects. When they receive a redirect
 * response, they throw an OAuthProblemException, with properties
 * HttpResponseMessage.STATUS_CODE = the redirect code
 * HttpResponseMessage.LOCATION = the redirect URL. Such a redirect can't be
 * handled at the HTTP level, if the second request must carry another OAuth
 * signature (with different parameters). For example, Google's Service Provider
 * routinely redirects requests for access to protected resources, and requires
 * the redirected request to be signed.
 * 
 * @author John Kristian
 */
public abstract class OAuthClient {

    /** Get a fresh request token from the service provider. */
    public void getRequestToken(OAuthAccessor accessor, String httpMethod)
            throws IOException, OAuthException, URISyntaxException {
        getRequestToken(accessor, httpMethod, null);
    }

    /** Get a fresh request token from the service provider. */
    public void getRequestToken(OAuthAccessor accessor, String httpMethod,
            Collection<? extends Map.Entry> parameters) throws IOException,
            OAuthException, URISyntaxException {
        accessor.accessToken = null;
        accessor.tokenSecret = null;
        {
            // This code supports the 'Variable Accessor Secret' extension
            // described in http://oauth.pbwiki.com/AccessorSecret
            Object accessorSecret = accessor
                    .getProperty(OAuthConsumer.ACCESSOR_SECRET);
            if (accessorSecret != null) {
                List<Map.Entry> p = (parameters == null) ? new ArrayList<Map.Entry>(
                        1)
                        : new ArrayList<Map.Entry>(parameters);
                p.add(new OAuth.Parameter("oauth_accessor_secret",
                        accessorSecret.toString()));
                parameters = p;
                // But don't modify the caller's parameters.
            }
        }
        OAuthMessage response = invoke(accessor, httpMethod,
                accessor.consumer.serviceProvider.requestTokenURL, parameters);
        accessor.requestToken = response.getParameter("oauth_token");
        accessor.tokenSecret = response.getParameter("oauth_token_secret");
        if (accessor.requestToken == null) {
            OAuthProblemException problem = new OAuthProblemException(
                    "parameter_absent");
            problem.setParameter("oauth_parameters_absent", "oauth_token");
            problem.getParameters().putAll(response.getDump());
            throw problem;
        }
    }

    public void getRequestToken(OAuthAccessor accessor) throws IOException,
            OAuthException, URISyntaxException {
        getRequestToken(accessor, null);
    }

    /**
     * Construct a request message, send it to the service provider and get the
     * response.
     * 
     * @return the response
     * @throws URISyntaxException
     *                 the given url isn't valid syntactically
     * @throws OAuthProblemException
     *                 the HTTP response status code was not OK
     */
    public OAuthMessage invoke(OAuthAccessor accessor, String httpMethod,
            String url, Collection<? extends Map.Entry> parameters)
    throws IOException, OAuthException, URISyntaxException {
        String ps = (String) accessor.consumer.getProperty(PARAMETER_STYLE);
        ParameterStyle style = (ps == null) ? ParameterStyle.BODY : Enum
                .valueOf(ParameterStyle.class, ps);
        OAuthMessage request = accessor.newRequestMessage(httpMethod, url,
                parameters);
        Object accepted = accessor.consumer.getProperty(ACCEPT_ENCODING);
        if (accepted != null) {
            request.getHeaders().add(
                    new OAuth.Parameter(HttpMessage.ACCEPT_ENCODING, accepted
                            .toString()));
        }
        return invoke(request, style);
    }

    /**
     * The name of the OAuthConsumer property whose value is the ParameterStyle
     * to be used by invoke.
     */
    public static final String PARAMETER_STYLE = "parameterStyle";

    /**
     * The name of the OAuthConsumer property whose value is the Accept-Encoding
     * header in HTTP requests.
     */
    public static final String ACCEPT_ENCODING = "HTTP.header." + HttpMessage.ACCEPT_ENCODING;

    /**
     * Construct a request message, send it to the service provider and get the
     * response.
     * 
     * @return the response
     * @throws URISyntaxException
     *                 the given url isn't valid syntactically
     * @throws OAuthProblemException
     *                 the HTTP response status code was not OK
     */
    public OAuthMessage invoke(OAuthAccessor accessor, String url,
            Collection<? extends Map.Entry> parameters) throws IOException,
            OAuthException, URISyntaxException {
        return invoke(accessor, null, url, parameters);
    }

    /** @deprecated Use invoke(OAuthMessage, ParameterStyle) instead. */
    public OAuthMessage invoke(OAuthMessage request) throws IOException,
            OAuthException {
        return invoke(request, ParameterStyle.BODY);
    }

    /**
     * Send a request message to the service provider and get the response.
     * 
     * @return the response
     * @throws IOException
     *                 failed to communicate with the service provider
     * @throws OAuthProblemException
     *                 the HTTP response status code was not OK
     */
    /** Send a message to the service provider and get the response. */
    public OAuthMessage invoke(OAuthMessage request, ParameterStyle style)
            throws IOException, OAuthException {
        final boolean isPost = POST.equalsIgnoreCase(request.method);
        InputStream body = request.getBodyAsStream();
        if (style == ParameterStyle.BODY && !(isPost && body == null)) {
            style = ParameterStyle.QUERY_STRING;
        }
        String url = request.URL;
        final List<Map.Entry<String, String>> headers =
            new ArrayList<Map.Entry<String, String>>(request.getHeaders());
        switch (style) {
        case QUERY_STRING:
            url = OAuth.addParameters(url, request.getParameters());
            break;
        case BODY: {
            byte[] form = OAuth.formEncode(request.getParameters()).getBytes(
                    request.getBodyEncoding());
            headers.add(new OAuth.Parameter(HttpMessage.CONTENT_TYPE,
                    OAuth.FORM_ENCODED));
            headers.add(new OAuth.Parameter(CONTENT_LENGTH, form.length + ""));
            body = new ByteArrayInputStream(form);
            break;
        }
        case AUTHORIZATION_HEADER:
            headers.add(new OAuth.Parameter("Authorization", request
                    .getAuthorizationHeader("")));
            // Find the non-OAuth parameters:
            List<Map.Entry<String, String>> others = request.getParameters();
            if (others != null && !others.isEmpty()) {
                others = new ArrayList<Map.Entry<String, String>>(others);
                for (Iterator<Map.Entry<String, String>> p = others.iterator(); p
                        .hasNext();) {
                    if (p.next().getKey().startsWith("oauth_")) {
                        p.remove();
                    }
                }
                // Place the non-OAuth parameters elsewhere in the request:
                if (isPost && body == null) {
                    byte[] form = OAuth.formEncode(others).getBytes(
                            request.getBodyEncoding());
                    headers.add(new OAuth.Parameter(HttpMessage.CONTENT_TYPE,
                            OAuth.FORM_ENCODED));
                    headers.add(new OAuth.Parameter(CONTENT_LENGTH, form.length
                            + ""));
                    body = new ByteArrayInputStream(form);
                } else {
                    url = OAuth.addParameters(url, others);
                }
            }
            break;
        }
        final HttpMessage httpRequest = new HttpMessage(request.method, new URL(url), body);
        httpRequest.headers.addAll(headers);
        HttpResponseMessage httpResponse = invoke(httpRequest);
        httpResponse = HttpMessageDecoder.decode(httpResponse);
        OAuthMessage response = new OAuthResponseMessage(httpResponse);
        if (httpResponse.getStatusCode() != HttpResponseMessage.STATUS_OK) {
            OAuthProblemException problem = new OAuthProblemException();
            try {
                response.getParameters(); // decode the response body
            } catch (IOException ignored) {
            }
            problem.getParameters().putAll(response.getDump());
            try {
                InputStream b = response.getBodyAsStream();
                if (b != null) {
                    b.close(); // release resources
                }
            } catch (IOException ignored) {
            }
            throw problem;
        }
        return response;
    }

    /** Where to place parameters in an HTTP message. */
    public enum ParameterStyle {
        AUTHORIZATION_HEADER, BODY, QUERY_STRING;
    };

    protected static final String PUT = OAuthMessage.PUT;
    protected static final String POST = OAuthMessage.POST;
    protected static final String DELETE = OAuthMessage.DELETE;
    protected static final String CONTENT_LENGTH = HttpMessage.CONTENT_LENGTH;

    /**
     * Send an HTTP request and return the response.
     * 
     * @param method
     *                the HTTP request method; e.g. "GET" or "POST"
     * @param url
     *                identifies the HTTP server and resource
     * @param headers
     *                HTTP request headers, in addition to the standard headers.
     *                May be empty, to indicate that no additional headers are
     *                needed
     * @param body
     *                HTTP request body, or null to indicate that a body should
     *                not be transmitted
     * @param bodyEncoding
     *                the character encoding of the request body
     * 
     * @return the HTTP response, including the OAuth parameters if the response
     *         was successful (status 200).
     */
    protected abstract HttpResponseMessage invoke(HttpMessage request)
            throws IOException;

}
