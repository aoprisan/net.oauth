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
import net.oauth.OAuthConsumer;
import net.oauth.OAuthServiceProvider;
import org.apache.commons.httpclient.HttpMethod;

/** A trivial consumer of the 'friends_timeline' service at Twitter. */
public class TwitterConsumer extends HttpServlet {

    private static final OAuthServiceProvider SERVICE_PROVIDER = new OAuthServiceProvider //
    ("http://twitter.com/oauth/request_token", //
            "http://twitter.com/oauth/authorize", //
            "http://twitter.com/oauth/access_token");

    public static final OAuthConsumer CONSUMER = new OAuthConsumer //
    (Callback.PATH, "68wbb4edygtm", "3lp4lakz5t7ogew3umgpg9k2z6anujj0",
            SERVICE_PROVIDER);
    static {
        CONSUMER.setProperty("name", "twitter");
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
            HttpMethod result = CookieConsumer
                    .invoke(
                            CONSUMER,
                            credentials,
                            "http://twitter.com/statuses/friends_timeline/jmkristian.xml",
                            null);
            String responseBody = result.getResponseBodyAsString();
            response.setContentType("text/plain");
            PrintWriter out = response.getWriter();
            out.println("twitter said:");
            out.print(responseBody);
        } catch (Exception e) {
            CookieConsumer.handleException(e, request, response, CONSUMER);
        }
    }

    private static final long serialVersionUID = 1L;

}
