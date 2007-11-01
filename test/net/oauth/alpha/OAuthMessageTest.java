package net.oauth.alpha;

import java.util.TreeMap;
import junit.framework.TestCase;

public class OAuthMessageTest extends TestCase {

    private static final String[] CASES =
    // label, input, expected result
    { "one parameter", "a=b", "a=b" //
	    , "two parameters", "a=b&c=d", "a=b&c=d" //
	    , "sort values", "a=x!y&a=x+y", "a=x%20y&a=%21y" //
	    , "sort names", "x!y=a&x=a", "x=a&x%21y=a" //
    };

    public void testParseResponseString() {
	OAuthMessage subject = new OAuthMessage();
	int c = 3; // two parameters
	subject.parseResponseString(CASES[c + 1]);
	assertEquals(CASES[c], CASES[c + 2], subject
		.normalizeRequestParameters());
    }

    public void testCases() {
	StringBuffer errors = new StringBuffer();
	for (int c = 0; c < CASES.length; c += 3) {
	    String label = CASES[c];
	    String input = CASES[c + 1];
	    String expected = CASES[c + 2];
	    OAuthMessage subject = new OAuthMessage();
	    subject.setAttitionalProperties(new TreeMap<String, String>());
	    subject.parseResponseString(input);
	    String actual = subject.normalizeRequestParameters();
	    if (!expected.equals(actual)) {
		if (errors.length() > 0)
		    errors.append(", ");
		errors.append(label).append(" ").append(actual);
	    }
	}
	if (errors.length() > 0)
	    fail(errors.toString());
    }

}
