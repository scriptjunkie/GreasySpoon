// Captcha-based whitelist by scriptjunkie
// This file imports a list of 
import java.io.*;
public class DatabaseBuilder{
//reCaptcha and database configuration file location
private static String configFileLocation = "/usr/local/GreasySpoon/CaptchaWhitelist.conf";
//Contains the following JDBC database parameters
private static String connectString = null, dbUser = null, dbPass = null, dbDriver = null, dbDriverJarPath = null;

//These are the status codes for the domains in the database.
private static final int UNSET = 0;
private static final int ALLOW = 1;
private static final int BLOCK = 2;
private static final int TODAY = 3; //allows temporarily
private static java.sql.Connection conn = null;

/**
 * Reads in a single domain
 */
public static void main(String[] args){
	if(args.length == 0){
		System.out.println("Provide a domain list file to add to the database!\n"
			+"Example: java DatabaseBuilder domainList.txt");
		return;
	}
	if(connectString == null) //First load props if necessary
		loadProperties();
	try{ //Connect to or create the database
		conn = getDbConnection();
		BufferedReader stdinReader = new BufferedReader(new FileReader(args[0]));
		String domain;
		while((domain = stdinReader.readLine()) != null)
			doDomainAction("Always", domain);
	}catch(Exception ex){
		ex.printStackTrace();
	}
}

/**
 * Given a verified domain, applies a given action to the domain, marking it as 
 * allowed, blocked, or temporarily allowed.
 */
private static void doDomainAction(String action, String domain) {
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
		connectString = prop.getProperty("connectString");
		dbUser = prop.getProperty("dbUser");
		dbPass = prop.getProperty("dbPass");
		dbDriver = prop.getProperty("dbDriver");
		dbDriverJarPath = prop.getProperty("dbDriverJarPath");
	} catch (java.io.IOException ex) {
		ex.printStackTrace();
	}
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
}
