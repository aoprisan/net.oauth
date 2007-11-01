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
