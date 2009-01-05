/*
 * Copyright 2009 John Kristian
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

package net.oauth.example.desktop;

import com.centerkey.utils.BareBonesBrowserLaunch;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.Collection;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import net.oauth.OAuth;
import net.oauth.OAuthAccessor;
import net.oauth.OAuthConsumer;
import net.oauth.OAuthException;
import net.oauth.OAuthMessage;
import net.oauth.OAuthProblemException;
import net.oauth.client.OAuthClient;
import net.oauth.client.httpclient3.HttpClient3;
import net.oauth.http.HttpMessage;
import org.mortbay.jetty.Handler;
import org.mortbay.jetty.Request;
import org.mortbay.jetty.Server;
import org.mortbay.jetty.handler.AbstractHandler;

/**
 * An OAuth accessor that obtains authorization by launching a browser, via
 * which the user can authenticate to the service provider. This is annoying,
 * because it leaves a browser window open on the user's desktop. Microsoft
 * Internet Explorer will ask "Do you want to close this window?" But it doesn't
 * close the window automatically.
 * <p>
 * The implementation involves an embedded web server (Jetty). To obtain
 * authorization, {@link access} launches a browser and directs it to the
 * service provider, which eventually redirects it back to the web server in
 * this class, which causes {@link access} to proceed with getting its OAuth
 * access token and accessing the protected resource.
 * <p>
 * If the user simply closes the browser window, {@link access} won't return.
 * Perhaps this could be handled better with some JavaScript fu to notify the
 * embedded web server. {@link access} would throw an exception in this case, I
 * imagine.
 * 
 * @author John Kristian
 */
public class DesktopAccessor {

    public DesktopAccessor(OAuthConsumer consumer) {
        oauth = new OAuthAccessor(consumer);
    }

    /**
     * In addition to containing OAuth parameters, this is used as a monitor to
     * coordinate the threads executing access and the threads in the embedded
     * web server.
     */
    private final OAuthAccessor oauth;

    private OAuthClient client = DEFAULT_CLIENT;

    public OAuthClient getClient() {
        return client;
    }

    public void setClient(OAuthClient client) {
        this.client = client;
    }

    /**
     * Access a protected resource.
     * 
     * @return the response from the service provider
     * @throws OAuthException
     *             the OAuth protocol didn't proceed smoothly
     */
    public OAuthMessage access(String httpMethod, String resourceURL, Collection<? extends Map.Entry> parameters)
            throws Exception {
        try {
            Server server = null;
            try {
                synchronized (oauth) {
                    String authorizationURL = null;
                    while (oauth.accessToken == null) {
                        getClient().getRequestToken(oauth);
                        if (authorizationURL == null) {
                            final int callbackPort = getEphemeralPort();
                            final String callbackURL = "http://localhost:" + callbackPort + CALLBACK_PATH;
                            authorizationURL = OAuth.addParameters(oauth.consumer.serviceProvider.userAuthorizationURL //
                                    , "oauth_token", oauth.requestToken //
                                    , "oauth_callback", callbackURL //
                                    );
                            server = new Server(callbackPort);
                            server.setHandler(newCallback());
                            server.start();
                        }
                        BareBonesBrowserLaunch.browse(authorizationURL);
                        oauth.wait();
                        if (oauth.accessToken == null) {
                            getClient().getAccessToken(oauth, null, null);
                        }
                    }
                }
            } finally {
                if (server != null) {
                    try {
                        server.stop();
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            }
            return getClient().invoke(oauth, httpMethod, resourceURL, parameters);
        } catch (OAuthProblemException p) {
            StringBuilder msg = new StringBuilder();
            String problem = p.getProblem();
            if (problem != null) {
                msg.append(problem);
            }
            Object response = p.getParameters().get(HttpMessage.RESPONSE);
            if (response != null) {
                String eol = System.getProperty("line.separator", "\n");
                msg.append(eol).append(response);
            }
            // for (Map.Entry e : p.getParameters().entrySet())
            // msg.append(e.getKey()).append(": ")
            // .append(e.getValue()).append(eol);
            throw new OAuthException(msg.toString(), p);
        }
    }

    private static int getEphemeralPort() throws IOException {
        Socket s = new Socket();
        s.bind(null);
        try {
            return s.getLocalPort();
        } finally {
            s.close();
        }
    }

    protected void proceed(String requestToken) {
        synchronized (oauth) {
            if (requestToken == null || requestToken.equals(oauth.requestToken)) {
                oauth.notifyAll();
                return;
            }
        }
        System.err.println("ignored authorization of request token " + requestToken);
    }

    protected Handler newCallback() {
        return new Callback(this);
    }

    protected static class Callback extends AbstractHandler {

        protected Callback(DesktopAccessor accessor) {
            this.accessor = accessor;
        }

        protected final DesktopAccessor accessor;

        public void handle(String target, HttpServletRequest request, HttpServletResponse response, int dispatch)
                throws IOException, ServletException {
            if (!CALLBACK_PATH.equals(target)) {
                response.setStatus(HttpServletResponse.SC_NOT_FOUND);
            } else {
                conclude(response);
                accessor.proceed(request.getParameter("oauth_token"));
                ((Request) request).setHandled(true);
            }
        }

        protected void conclude(HttpServletResponse response) throws IOException {
            response.setStatus(HttpServletResponse.SC_OK);
            response.setContentType("text/html");
            final PrintWriter doc = response.getWriter();
            doc.println("<HTML>");
            doc.println("<body onLoad=\"window.close();\">");
            doc.println("Thank you.  You can close this window now.");
            doc.println("</body>");
            doc.println("</HTML>");
        }

    }

    private static final OAuthClient DEFAULT_CLIENT = new OAuthClient(new HttpClient3());
    private static final String CALLBACK_PATH = "/oauth/callback";

    static { // suppress log output from Jetty
        try {
            Logger.getLogger("org.mortbay.log").setLevel(Level.WARNING);
        } catch (Exception ignored) {
        }
        try {
            System.setProperty("org.apache.commons.logging.simplelog.log.org.mortbay.log", "warn");
        } catch (Exception ignored) {
        }
    }

}
