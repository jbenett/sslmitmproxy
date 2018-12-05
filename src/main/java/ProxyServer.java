import java.io.FileWriter;
import java.io.PrintWriter;

public class ProxyServer
{
    public static void main(String[] args) {
	final ProxyServer proxy = new ProxyServer(args);
	proxy.run();
    }

    private Error printUsage() {
	System.err.println(
	    "\n" +
	    "Usage: " +
	    "\n java " + ProxyServer.class + " <options>" +
	    "\n" +
	    "\n Where options can include:" +
	    "\n" +
	    "\n   [-keyStore <file>]           Key store details for" +
	    "\n   [-keyStorePassword <pass>]   certificates. Equivalent to" +
	    "\n   [-outputFile <filename>]     Default is stdout" +
	    "\n" +
	    "\n -outputFile specifies where the output from ProxyDataFilter will go." +
	    "\n By default, it is sent to stdout" +
	    "\n"
	    );

	System.exit(1);
	return null;
    }

    private Error printUsage(String s) {
	System.err.println("\n" + "Error: " + s);
	throw printUsage();
    }

    private HTTPSProxyEngine m_engine = null;
    
    private ProxyServer(String[] args)
    {
	// Default values.
	ProxyDataFilter requestFilter = new ProxyDataFilter();
	ProxyDataFilter responseFilter = new ProxyDataFilter();
	int localPort = 8001;
	String localHost = "localhost";

	int timeout = 0;

	try {
	    for (int i=0; i<args.length; i++)
	    {
		if (args[i].equals("-keyStore")) {
		    System.setProperty(JSSEConstants.KEYSTORE_PROPERTY,
				       args[++i]);
		} else if (args[i].equals("-keyStorePassword")) {
		    System.setProperty(
			JSSEConstants.KEYSTORE_PASSWORD_PROPERTY, args[++i]);
		}  else if (args[i].equals("-outputFile")) {
		    PrintWriter pw = new PrintWriter(new FileWriter(args[++i]), true);
		    requestFilter.setOutputPrintWriter(pw);
		    responseFilter.setOutputPrintWriter(pw);
		} else {
		    throw printUsage();
		}
	    }
	}
	catch (Exception e) {
	    throw printUsage();
	}

	if (timeout < 0) {
	    throw printUsage("Timeout must be non-negative");
	}

	final StringBuffer startMessage = new StringBuffer();

	startMessage.append("Initializing SSL proxy with the parameters:" +
	    "\n   Local host:       " + localHost + 
	    "\n   Local port:       " + localPort);
	startMessage.append("\n   (SSL setup could take a few seconds)");

	System.err.println(startMessage);

	try {
	    m_engine = 
		new HTTPSProxyEngine(new SocketFactory(),
				     new SSLSocketFactory(),
				     requestFilter,
				     responseFilter,
				     localHost,
				     localPort,
				     timeout);
	    
	    System.err.println("Proxy initialized, listening on port " + localPort);
	}
	catch (Exception e){
	    System.err.println("Could not initialize proxy:");
	    e.printStackTrace();
	    System.exit(2);
	}
    }

    public void run() 
    {
	m_engine.run();
	System.err.println("Engine exited");
	System.exit(0);
    }
}
