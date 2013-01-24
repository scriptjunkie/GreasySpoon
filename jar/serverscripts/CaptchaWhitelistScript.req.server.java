//------------------------------------------------------------------- 
// ==ServerScript==
// @name				CaptchaWhitelist
// @status on
// @description Whitelists by domain, allowing access to sites through reCaptcha
// @include		.*
// ==/ServerScript==
// --------------------------------------------------------------------

// Captcha-based whitelist by scriptjunkie

//reCaptcha and database configuration file location
private static String configFileLocation = "/usr/local/GreasySpoon/CaptchaWhitelist.conf";
//Contains the following entries
private static String reCaptchaPubkey = null, reCaptchaPrivkey = null, //recaptcha params
	//see http://www.google.com/recaptcha/whyrecaptcha to get your keys
	//Below are JDBC database parameters
	connectString = null, dbUser = null, dbPass = null, dbDriver = null, dbDriverJarPath = null;
private static int ACCESS_HOURS = 24; //number of hours a temporary allow will be good for

//These are the status codes for the domains in the database.
private static final int UNSET = 0;
private static final int ALLOW = 1;
private static final int BLOCK = 2;
private static final int TODAY = 3; //allows temporarily
private static java.sql.Connection conn = null;

/**
 * Processes a request
 */
public void main(HttpMessage httpMessage){
	if(connectString == null) //First load props if necessary
		loadProperties();
	try{ //Connect to or create the database
		conn = getDbConnection();
	}catch(Exception ex){
		ex.printStackTrace();
	}
	try{
	String reqHeaders = httpMessage.getRequestHeaders();
	String urlString = httpMessage.getUrl();
	if(reqHeaders.startsWith("CONNECT"))
		return; // wait till we get the real request
	int reqAction = requestAction(urlString);
	boolean denied = false;
	//First check if this is a CAPTCHA submission
	if(urlString.startsWith("http://whitelist.verify.scriptjunkie.us")){
		//First put all of the URL parameters into a map
		java.util.Map params = new java.util.HashMap();
		for(String s : new java.net.URL(urlString).getQuery().split("&"))
			params.put(s.substring(0, s.indexOf("=")), java.net.URLDecoder.decode(s.substring(s.indexOf("=") + 1)));
		//Verify the request
		if(verifyCaptcha(params.get("recaptcha_challenge_field").toString(), 
				params.get("recaptcha_response_field").toString())){

			//It's good, let's store the domain (just the SLD if more than 2 levels)
			if(requestAction(params.get("u").toString()) != BLOCK)
				doDomainAction(params.get("action").toString(), getShortDomain(params.get("u").toString()));
			
			//Redirect the user back to the original domain
			httpMessage.setHeaders("HTTP/1.1 302 Found\r\nContent-Type: text/html\r\n"
				+"CacheControl: no-cache\r\nPragma: no-cache\r\nLocation: " + params.get("u") + "\r\n\r\n");
			httpMessage.setBody("<!DOCTYPE html><html><head><title>Access Granted</title></head>"
				+"<body><h1>Access Granted</h1><p>You may now continue to your original site.</p></body></html>");
			return;
		}else{ //It's bad; they'll be blocked
			denied = true;
		}
	}
	if (denied || reqAction == UNSET){
		String reCaptchaForm = "<form action=\"http://whitelist.verify.scriptjunkie.us/\" method=\"get\">"
			+"<script type=\"text/javascript\" "
			+"src=\"http://www.google.com/recaptcha/api/challenge?k="
			+java.net.URLEncoder.encode(reCaptchaPubkey)+"\">"
			+"</script><noscript><iframe src=\"http://www.google.com/recaptcha/api/noscript?k="
			+java.net.URLEncoder.encode(reCaptchaPubkey)+"\""
			+"height=\"300\" width=\"500\" frameborder=\"0\"></iframe><br>"
			+"<textarea name=\"recaptcha_challenge_field\" rows=\"3\" cols=\"40\">"
			+"</textarea>"
			+"<input type=\"hidden\" name=\"recaptcha_response_field\""
			+"value=\"manual_challenge\">"
			+"</noscript>"
			+"<input type=\"radio\" name=\"action\" value=\"Always\"> Always allow<br>"
			+"<input type=\"radio\" name=\"action\" value=\"Now\" checked> Allow today<br>"
			+"<input type=\"radio\" name=\"action\" value=\"Block\"> Block <br>"
			+"<input type=\"hidden\" name=\"u\" value=\""+urlString+"\" />"
			+"<input type=\"submit\" name=\"submit\" value=\"Submit\">"
			+"</form>";

		httpMessage.setBody("<!DOCTYPE html><html><head><title>Unknown Site Access Confirmation</title></head>"
			+"<body><h1>Are you sure?</h1><p>You are about to head to an unknown site. If you don't want to be"
			+" bothered with this screen again, choose always allow.</p>"
			+ reCaptchaForm +"</body>"
			+"</html>");
		httpMessage.setHeaders("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nCacheControl: no-cache\r\nPragma: no-cache\r\n\r\n");
	//BLOCK gives no hope of escaping
	}else if(reqAction == BLOCK){
		httpMessage.setBody("<!DOCTYPE html><html><head><title>Access Denied</title></head>"
			+"<body><h1>Denied</h1><p>Access to this site has been denied. Sorry.</p></body></html>");
		httpMessage.setHeaders("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n");
	}
	}catch(java.io.IOException iox){
		iox.printStackTrace();
	}
}

/**
 * Decide whether to stop a request; default to UNSET, and ALLOW or BLOCK if marked in the db.
 */
private int requestAction(String urlString){
	//first check to ensure we aren't blocking ourselves
	if(urlString.startsWith("http://www.google.com/recaptcha/api/"))
		return ALLOW;
	java.sql.PreparedStatement ps = null;
	int retval = UNSET;
	java.sql.ResultSet rs = null;
	try{ //See if it's there
		ps = conn.prepareStatement("SELECT * FROM DOMAINS WHERE DOMAIN = ?");
		ps.setString(1, getShortDomain(urlString));
		rs = ps.executeQuery();
		if(rs.next()){
			if(rs.getInt(3) != TODAY // if it is marked temporary (TODAY), check dates
					|| new java.util.Date().getTime() - rs.getTimestamp(4).getTime()
					< 1000 * 60 * 60 * ACCESS_HOURS);
				retval = ALLOW;
			if(rs.getInt(3) == BLOCK) //if it's blocked; it's blocked!
				retval = BLOCK;
		}
		rs.close();
		ps.close();
	} catch (Exception e){
		e.printStackTrace();
	} finally {// release all open resources to avoid unnecessary memory usage
		try {
			rs.close();
		} catch (Exception sqle) {
		}
		try {
			ps.close();
		} catch (Exception sqle) {
		}
	}
	return retval;
}

/**
 * Given a verified domain, applies a given action to the domain, marking it as 
 * allowed, blocked, or temporarily allowed.
 */
private void doDomainAction(String action, String domain) {
	//Translate the action first
	java.sql.PreparedStatement ps = null;
	int newStatus = BLOCK; //block by default
	if(action.equals("Always")){
		newStatus = ALLOW;
	}else if(action.equals("Now")){
		newStatus = TODAY;
	}
	try{ //We try updating first, in case the domain is already there
		ps = conn.prepareStatement("UPDATE DOMAINS SET STATUS=? WHERE DOMAIN=?");
		ps.setInt(1, newStatus);
		ps.setString(2, domain);
		int numRowsModified = ps.executeUpdate();
		ps.close();
		if(numRowsModified == 0){ //If not, we need to make a new entry
			ps = conn.prepareStatement("INSERT INTO DOMAINS VALUES (?, ?, ?, CURRENT_TIMESTAMP)");
			ps.setString(1, domain);
			ps.setInt(2, 0);
			ps.setInt(3, newStatus);
			ps.executeUpdate();
			ps.close();
			//Astute observers will notice a lack of transactions; what happens if a record is added
			//between the update and insert statements? Well, then the insert will fail and dump an
			//exception. We really don't care, since we only need one confirmation to allow access.
		}
	} catch (Exception e){
		e.printStackTrace();
	} finally {// release all open resources to avoid unnecessary memory usage
		try {
			ps.close();
		} catch (Exception sqle) {
		}
	}
}

/**
 * Load properties
 */
private static void loadProperties(){
	java.util.Properties prop = new java.util.Properties();
	try{ //load the properties file
		prop.load(new java.io.FileInputStream(configFileLocation));
		//load the properties
		reCaptchaPubkey = prop.getProperty("reCaptchaPubkey");
		reCaptchaPrivkey = prop.getProperty("reCaptchaPrivkey");
		connectString = prop.getProperty("connectString");
		dbUser = prop.getProperty("dbUser");
		dbPass = prop.getProperty("dbPass");
		dbDriver = prop.getProperty("dbDriver");
		dbDriverJarPath = prop.getProperty("dbDriverJarPath");
		ACCESS_HOURS = Integer.parseInt(prop.getProperty("ACCESS_HOURS"));
	} catch (java.io.IOException ex) {
		ex.printStackTrace();
	}
}

/**
 * Gets a short domain from a URL (second-level domain if more than one level is present)
 */
private String getShortDomain(String u) throws java.net.MalformedURLException{
	String fullDomain = new java.net.URL(u).getHost();
	String[] pieces = fullDomain.split("\\.");
	//don't split numeric domains; e.g. 1.2.3.4 since they're probably IP's
	boolean numeric = false;
	for(int i = 0; i < pieces[0].length(); i++)
		numeric = numeric && pieces[0].charAt(i) >= '0' && pieces[0].charAt(i) <= '9';
	if(numeric)
		return fullDomain;
	//Otherwise we can just get the last one or two domains
	String shortDomain = pieces[pieces.length - 1];
	if(pieces.length > 1)
		return pieces[pieces.length - 2] + "." + shortDomain;
	return shortDomain;
}

/**
 * Verifies a reCaptcha
 * See: https://developers.google.com/recaptcha/docs/verify
 */
private boolean verifyCaptcha(String challenge, String response) throws java.io.IOException{
	String urlParameters = "privatekey="+java.net.URLEncoder.encode(reCaptchaPrivkey)
		+"&remoteip=127.0.0.1"
		+"&challenge="+java.net.URLEncoder.encode(challenge)
		+"&response="+java.net.URLEncoder.encode(response);
	byte[] parambytes = urlParameters.getBytes();
	String request = "http://www.google.com/recaptcha/api/verify";
	java.net.URL url = new java.net.URL(request); 
	java.net.HttpURLConnection connection = (java.net.HttpURLConnection) url.openConnection();			
	connection.setDoOutput(true);
	connection.setDoInput(true);
	connection.setInstanceFollowRedirects(false); 
	connection.setRequestMethod("POST"); 
	connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded"); 
	connection.setRequestProperty("charset", "utf-8");
	connection.setRequestProperty("Content-Length", "" + Integer.toString(parambytes.length));
	connection.setUseCaches (false);

	java.io.OutputStream wr = connection.getOutputStream ();
	wr.write(parambytes);
	wr.flush();
	java.io.InputStream is = connection.getInputStream ();
	byte[] replyBytes = new byte[10];
	int bytesRead = is.read(replyBytes);
	wr.close();
	connection.disconnect();
	return bytesRead >= 4 && new String(replyBytes, 0, 4).equals("true");
}

// loads the JDBC driver and gets a connection
private static java.sql.Connection getDbConnection() throws Exception{
	if(conn != null)
		return conn;
	System.err.println("Opening new database connection");
	try{
		Object o = Class.forName (dbDriver).newInstance();
	}catch(ClassNotFoundException ex){
		//System class loader is hacked up to load the db jar file
		//note: you can't simply load the class with a new class loader or the driver will fail to load
		Object classLoader = ClassLoader.getSystemClassLoader();
		java.lang.reflect.Method method= java.net.URLClassLoader.class.getDeclaredMethod("addURL", new Class[] { java.net.URL.class });
		method.setAccessible(true);
		method.invoke(classLoader, new Object[] { new java.io.File(dbDriverJarPath).toURL() });
		Class.forName (dbDriver).newInstance();
	}
	if(dbUser != null) //credentialed login
		conn = java.sql.DriverManager.getConnection(connectString, dbUser, dbPass);
	else
		conn = java.sql.DriverManager.getConnection(connectString);
	java.sql.Statement s = conn.createStatement();
	try{ //Ensure the table exists
		s.execute("CREATE TABLE DOMAINS(DOMAIN VARCHAR(250) PRIMARY KEY, RANK INT DEFAULT -1, STATUS INT DEFAULT 0, MODIFIED TIMESTAMP)");
		s.close();
	}catch(Exception ex){
	}
	return conn;
}
