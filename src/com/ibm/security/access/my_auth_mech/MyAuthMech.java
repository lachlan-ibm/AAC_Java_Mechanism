/*
 * Copyright contributors to the IBM Security Verify Access AAC Java Extension Authentication Mechanism project
*/


package com.ibm.security.access.my_auth_mech;

import java.util.Properties;
import java.util.logging.Logger;

import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonValue;

import com.ibm.security.access.extension.authn.AuthenticationMechanism;
import com.ibm.security.access.extension.authn.AuthenticationMechanismContext;
import com.ibm.security.access.extension.authn.AuthenticationMechanismException;
import com.ibm.security.access.extension.authn.AuthenticationMechanismResult;
import com.ibm.security.access.extension.authn.task.HtmlPagePauseTask;
import com.ibm.security.access.extension.authn.task.JsonPagePauseTask;

public class MyAuthMech implements AuthenticationMechanism {
	private static final String CLASS_NAME = MyAuthMech.class.getName();
	private static final Logger LOGGER = Logger.getLogger(CLASS_NAME);

	public MyAuthMech() {
		
	}
	
	@Override
	public AuthenticationMechanismResult execute(AuthenticationMechanismContext context)
			throws AuthenticationMechanismException {
		String methodName = "MyAuthMech.execute";
		LOGGER.entering(CLASS_NAME, methodName);
		ContextHelper contextHelper = new ContextHelper(context);
		//boolean api = contextHelper.isApi();
		try {
			/*
			if (api) {
				return jsonResponse(contextHelper);
			} else {
				return htmlResponse(contextHelper);
			}
			*/
			return htmlResponse(contextHelper);
		} finally {
			LOGGER.exiting(CLASS_NAME, methodName);
		}
	}
	
	private AuthenticationMechanismResult jsonResponse(ContextHelper contextHelper) 
			throws AuthenticationMechanismException {
		JsonPagePauseTask task = new JsonPagePauseTask();
		JsonObjectBuilder contentBuilder = Json.createObjectBuilder();
		JsonArray testOptions = contextHelper.getParameters();
		String errorString = contextHelper.getErrorMessage();
        int rc = contextHelper.getResponseStatusCode();
        LOGGER.finest("RC: " + rc);
        if (rc > 0) {
            task.setStatusCode(rc);
        }
		if (testOptions.isEmpty()) {
			return AuthenticationMechanismResult.pause(task);
		}
		else if (errorString != null && !errorString.isEmpty()) {
			throw new AuthenticationMechanismException(errorString);
		} else {
			for (Object o : testOptions.toArray()) {
				JsonObject json = (JsonObject) o;
				String macro = json.getString("macro");
				String key = json.getString("key");
				JsonValue value = json.get("value");
				LOGGER.finest(value.toString());
				contentBuilder.add(key, macro);
				task.setMacro(macro, value);
			}
			contentBuilder.add("stateId", "@STATE@");
			contentBuilder.add("mechanism", "@MECHANISM_ID@");
			task.setPageContent(contentBuilder.build());
			LOGGER.finest(task.getMacros().toString());
			//throw new AuthenticationMechanismException("test");
		}
	    return AuthenticationMechanismResult.pause(task);
	}
	
	private AuthenticationMechanismResult htmlResponse(ContextHelper contextHelper) 
			throws AuthenticationMechanismException {
		HtmlPagePauseTask task = new HtmlPagePauseTask();
		JsonArray testOptions = contextHelper.getParameters();
		String errorString = contextHelper.getErrorMessage();
        int rc = contextHelper.getResponseStatusCode();
        LOGGER.finest("RC: " + rc);
        if (rc > 0) {
            task.setStatusCode(rc);
        }
		if(testOptions.isEmpty()) {
			return AuthenticationMechanismResult.pause(task);
		}
		else if (errorString != null && !errorString.isEmpty()) {
			throw new AuthenticationMechanismException(errorString);
		} else {
			StringBuilder sb = new StringBuilder();
			for (Object o: testOptions.toArray()) {
				JsonObject json = (JsonObject) o;
				LOGGER.finest(json.toString());
				String macro = json.getString("macro");
				String key = json.getString("key");
				String value = json.get("value").toString();
				
				sb.append(key + ": " + macro + "\n");
				task.setMacro(macro, value);
			}
			sb.append("action: @ACTION@\nmechanism: @MECHANISM@\n");
			task.setPageContent(sb.toString());
		    LOGGER.finest("Content: " + sb.toString());
			return AuthenticationMechanismResult.pause(task);			
		}
	}

	@Override
	public void shutdown() {
		LOGGER.entering(CLASS_NAME, "shutdown");

		LOGGER.exiting(CLASS_NAME, "shutdown");
	}

	@Override
	public void startup(Properties props) {
		String method = "startup";
		LOGGER.entering(CLASS_NAME, method);
		LOGGER.exiting(CLASS_NAME, method);
	}
	
	public void init(Properties props) {
		props.getProperty("test");
		
	}


}
