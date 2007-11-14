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

package net.oauth;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class OAuth {

    /** The encoding used to represent characters as bytes. */
    public static final String ENCODING = "UTF-8";

    /** The MIME type for a sequence of OAuth parameters. */
    public static final String FORM_ENCODED = "application/x-www-form-urlencoded";

    public static boolean isFormEncoded(String contentType) {
	if (contentType == null) {
	    return false;
	}
	int semi = contentType.indexOf(";");
	if (semi >= 0) {
	    contentType = contentType.substring(0, semi);
	}
	return FORM_ENCODED.equalsIgnoreCase(contentType.trim());
    }

    public static String formEncode(Iterable<? extends Map.Entry> parameters)
	    throws IOException {
	ByteArrayOutputStream b = new ByteArrayOutputStream();
	formEncode(parameters, b);
	return new String(b.toByteArray());
    }

    public static void formEncode(Iterable<? extends Map.Entry> parameters,
	    OutputStream into) throws IOException {
	if (parameters != null) {
	    boolean first = true;
	    for (Map.Entry parameter : parameters) {
		if (first) {
		    first = false;
		} else {
		    into.write('&');
		}
		into.write(percentEncode(toString(parameter.getKey()))
			.getBytes());
		into.write('=');
		into.write(percentEncode(toString(parameter.getValue()))
			.getBytes());
	    }
	}
    }

    public static List<Parameter> decodeForm(String form) {
	List<Parameter> list = new ArrayList<Parameter>();
	if (form != null) {
	    for (String nvp : form.split("\\&")) {
		int equals = nvp.indexOf('=');
		String name;
		String value;
		if (equals < 0) {
		    name = decodePercent(nvp);
		    value = null;
		} else {
		    name = decodePercent(nvp.substring(0, equals));
		    value = decodePercent(nvp.substring(equals + 1));
		}
		list.add(new Parameter(name, value));
	    }
	}
	return list;
    }

    public static String percentEncode(String s) {
	if (s == null) {
	    return "";
	}
	try {
	    return URLEncoder.encode(s, ENCODING)
		    // OAuth encodes some characters differently:
		    .replace("+", "%20").replace("*", "%2A")
		    .replace("%7E", "~");
	    // This could be done faster with more hand-crafted code.
	} catch (UnsupportedEncodingException wow) {
	    throw new RuntimeException(wow.getMessage(), wow);
	}
    }

    public static String decodePercent(String s) {
	try {
	    return URLDecoder.decode(s, ENCODING);
	    // This implements http://oauth.pbwiki.com/FlexibleDecoding
	} catch (java.io.UnsupportedEncodingException wow) {
	    throw new RuntimeException(wow.getMessage(), wow);
	}
    }

    /**
         * Construct a Map containing the a copy of the given parameters. If
         * several parameters have the same name, the Map will contain the first
         * value, only.
         */
    public static Map<String, String> newMap(Iterable<? extends Map.Entry> from) {
	Map<String, String> map = new HashMap<String, String>();
	if (from != null) {
	    for (Map.Entry f : from) {
		String key = toString(f.getKey());
		if (!map.containsKey(key)) {
		    map.put(key, toString(f.getValue()));
		}
	    }
	}
	return map;
    }

    /** Construct a list of Parameters from name, value, name, value... */
    public static List<Parameter> newList(String... parameters) {
	List<Parameter> list = new ArrayList<Parameter>(parameters.length / 2);
	for (int p = 0; p + 1 < parameters.length; p += 2) {
	    list.add(new Parameter(parameters[p], parameters[p + 1]));
	}
	return list;
    }

    public static class Parameter implements Map.Entry<String, String> {

	public Parameter(String key, String value) {
	    this.key = key;
	    this.value = value;
	}

	private final String key;

	private String value;

	public String getKey() {
	    return key;
	}

	public String getValue() {
	    return value;
	}

	public String setValue(String value) {
	    try {
		return this.value;
	    } finally {
		this.value = value;
	    }
	}

	@Override
	public String toString() {
	    return percentEncode(getKey()) + '=' + percentEncode(getValue());
	}
    }

    private static final String toString(Object from) {
	return (from == null) ? null : from.toString();
    }

    public static String addParameters(String url, String... parameters)
	    throws IOException {
	String form = formEncode(newList(parameters));
	if (form.length() <= 0) {
	    return url;
	} else {
	    return url + ((url.indexOf("?") < 0) ? '?' : '&') + form;
	}
    }

}
