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

public class OAuthParameterEncoderTest extends TestCase {

    private static final OAuthParameterEncoder SUBJECT = new OAuthParameterEncoder();

    static final String[] CASES =
    // label, input, expected result
    { "ALPHA", "abcABC", "abcABC" //
	    , "DIGIT", "123", "123" //
	    , "unreserved", "-._~", "-._~" //
	    , "percent", "%", "%25" //
	    , "not unreserved", "&=*", "%26%3D%2A" //
	    , "LF", "\n", "%0A" //
	    , "SP", " ", "%20" //
	    , "DEL", "\u007F", "%7F" //
	    , "Latin", "\u0080", "%C2%80" //
	    , "CJK", "\u3001", "%E3%80%81" //
    };

    public void testCases() {
	StringBuffer errors = new StringBuffer();
	for (int c = 0; c < CASES.length; c += 3) {
	    String label = CASES[c];
	    String input = CASES[c + 1];
	    String expected = CASES[c + 2];
	    String actual = SUBJECT.encode(input);
	    if (!expected.equals(actual)) {
		if (errors.length() > 0)
		    errors.append(", ");
		errors.append(label).append(" ").append(actual);
		// assertEquals(CASES[c + 1], SUBJECT.encode(CASES[c]));
	    }
	}
	if (errors.length() > 0)
	    fail(errors.toString());
    }

}
