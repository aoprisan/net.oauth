/*
 * Copyright 2007 Netflix, Inc.
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

package net.oauth.example.consumer.webapp;

import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import net.oauth.OAuth;
import net.oauth.OAuthConsumer;
import net.oauth.OAuthMessage;
import net.oauth.OAuthServiceProvider;
import net.oauth.server.OAuthServlet;
import org.apache.commons.httpclient.HttpMethod;

/** A trivial consumer of the 'echo' service at term.ie. */
public class TermieConsumer extends HttpServlet {

    private static final String NAME = "term.ie";

    private static final OAuthServiceProvider SERVICE_PROVIDER = new OAuthServiceProvider //
    ("http://term.ie/oauth/example/request_token.php" //
            // user authorization is not required:
            , UserAuthorizationStub.PATH //
            , "http://term.ie/oauth/example/access_token.php");

    public static final OAuthConsumer CONSUMER = new OAuthConsumer //
    ("- not used -", "key", "secret", SERVICE_PROVIDER);
    static {
        CONSUMER.setProperty("name", NAME);
    }

    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        CookieConsumer.ALL_CONSUMERS.add(CONSUMER);
    }

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        try {
            CookieMap credentials = CookieConsumer.getCredentials(request,
                    response, CONSUMER);
            String accessToken = credentials.get(NAME + ".accessToken");
            String tokenSecret = credentials.get(NAME + ".tokenSecret");
            OAuthMessage message = OAuthServlet.getMessage(request, null);
            message
                    .addParameter(new OAuth.Parameter("oauth_token",
                            accessToken));
            response.setContentType("text/plain");
            PrintWriter out = response.getWriter();
            out.println("term.ie said:");
            // Try it twice:
            out.println(invoke(tokenSecret, message));
            out.println(invoke(tokenSecret, message));
        } catch (Exception e) {
            CookieConsumer.handleException(e, request, response, CONSUMER);
        }
    }

    private static String invoke(String tokenSecret, OAuthMessage message)
            throws Exception {
        HttpMethod result = CookieConsumer.invoke(CONSUMER,
                "http://term.ie/oauth/example/echo_api.php", tokenSecret,
                message.getParameters());
        String responseBody = result.getResponseBodyAsString();
        return responseBody;
    }

    private static final long serialVersionUID = 1L;

}
