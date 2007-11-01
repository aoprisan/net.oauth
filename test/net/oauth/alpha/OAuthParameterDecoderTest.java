package net.oauth.alpha;

import junit.framework.TestCase;

public class OAuthParameterDecoderTest extends TestCase {

    private static final OAuthParameterDecoder SUBJECT = new OAuthParameterDecoder();

    private static final String[] STANDARD = OAuthParameterEncoderTest.CASES;

    private static final String[] FLEXIBLE =
    // label, input, expected result
    { "SP", " ", "+" //
	    , "slash", "/", "%2F" //
	    , "not unreserved", "&=*", "%26%3D%2A" //
	    , "lower case hex", "/=*\u3001", "%2f%3d%2a%e3%80%81" //
    };

    public void testStandard() {
	test(STANDARD);
    }

    public void testFlexible() {
	test(FLEXIBLE);
    }

    private static void test(String[] cases) {
	StringBuffer errors = new StringBuffer();
	for (int c = 0; c < cases.length; c += 3) {
	    String label = cases[c];
	    String input = cases[c + 2];
	    String expected = cases[c + 1];
	    String actual = SUBJECT.decode(input);
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
