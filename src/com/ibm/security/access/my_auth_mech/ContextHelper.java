/**
 * Copyright IBM 2021
 */

package com.ibm.security.access.my_auth_mech;


import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.logging.Logger;

import javax.json.Json;
import javax.json.JsonArray;

import com.ibm.security.access.extension.authn.AuthenticationMechanismContext;

public class ContextHelper {
	private AuthenticationMechanismContext context;
	private static final String CLASS_NAME = ContextHelper.class.getName();
	private static final Logger LOGGER = Logger.getLogger(CLASS_NAME);
	
	public ContextHelper(AuthenticationMechanismContext context) {
		this.context = context;

	}
	
	/**
	 * Expected format:
	 * [
	 * 		{"macro": "@MACRO@",
	 * 		 "key": "a key",
	 * 		 "value": "some value"
	 *		},
	 *		{"macro": "@ANOTHER_MACRO@",
	 *		 "key" :"another key",
	 *		 "value": "another value"
	 *		}
	 *	]
	 * JSONArray should be stringified then Base64 URL encoded.
	 * 
	 * @return
	 */
	public JsonArray getParameters() {
		String method = "getParameters";
		LOGGER.entering(CLASS_NAME, method);
		String b64s = context.getRequest().getParameter("testParameters");
		if (b64s == null || b64s.isEmpty()) {
			return Json.createArrayBuilder().build();
		}
		LOGGER.finest("b64 String: " + b64s);
		String in = new String(Base64.getUrlDecoder().decode(b64s));
		LOGGER.finest("decoded: " + in);
		InputStream stream = new ByteArrayInputStream(in.getBytes(StandardCharsets.UTF_8));
		JsonArray testOptions = Json.createReader(stream).readArray();
		LOGGER.exiting(CLASS_NAME, method);
		return testOptions;
	}
	
	public int getResponseStatusCode() {
		String statusCodeStr = context.getRequest().getParameter("rc");
		if (statusCodeStr != null && !statusCodeStr.isEmpty()) {
			return Integer.parseInt(statusCodeStr);
		}
		else {
			return -1;
		}
	}
	
	public String getErrorMessage() {
		return context.getRequest().getParameter("errorMessage");		
	}
	
	public boolean isApi() {
		String method = "isApi";
		LOGGER.entering(CLASS_NAME, method);
		boolean result = false;
		String uri = context.getRequest().getUri();
		LOGGER.finest("URI: " + uri);
		List<String> headerValues = context.getRequest().getHeaders("Accept");
		if (uri.contains("apiauthsvc") && headerValues.contains("application/json")) {
			result = true;
		}
		LOGGER.exiting(CLASS_NAME, method, result);
		return result;
	}
}
