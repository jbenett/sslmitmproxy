//Based on HTTPProxySnifferEngine.java from The Grinder distribution.
// The Grinder distribution is available at http://grinder.sourceforge.net/

import javax.naming.ldap.LdapName;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

public class HTTPSProxyEngine extends ProxyEngine {

    public static final String ACCEPT_TIMEOUT_MESSAGE = "Listen time out";

    private String tempHost;
    private int tempPort;

    private final Pattern m_httpsConnectPattern;

    private final ProxySSLEngine proxySSLEngine;

    public HTTPSProxyEngine(SocketFactory plainSocketFactory,
                            SSLSocketFactory sslSocketFactory,
                            ProxyDataFilter requestFilter,
                            ProxyDataFilter responseFilter,
                            String localHost,
                            int localPort,
                            int timeout)
            throws IOException, PatternSyntaxException {
        super(plainSocketFactory,
                requestFilter,
                responseFilter,
                new ConnectionDetails(localHost, localPort, "", -1, false),
                timeout);

        m_httpsConnectPattern =
                Pattern.compile("^CONNECT[ \\t]+([^:]+):(\\d+).*\r\n\r\n",
                        Pattern.DOTALL);

        assert sslSocketFactory != null;
        proxySSLEngine = new ProxySSLEngine(sslSocketFactory, requestFilter, responseFilter);

    }

    public void run() {
        final byte[] buffer = new byte[40960];

        while (true) {
            try {
                final Socket localSocket = getServerSocket().accept();

                // Retrieve potential connect message
                final BufferedInputStream in =
                        new BufferedInputStream(localSocket.getInputStream(),buffer.length);

                in.mark(buffer.length);

                final int bytesRead = in.read(buffer);

                final String line = bytesRead > 0 ?
                                new String(buffer, 0, bytesRead, "US-ASCII") : "";

                final Matcher httpsConnectMatcher =
                        m_httpsConnectPattern.matcher(line);

                // Connect message found
                if (httpsConnectMatcher.find()) {
                    while (in.read(buffer, 0, in.available()) > 0) {
                    }

                    final String remoteHost = httpsConnectMatcher.group(1);
                    final int remotePort = Integer.parseInt(httpsConnectMatcher.group(2));
                    final String target = remoteHost + ":" + remotePort;

                    System.err.println("******* Connecting to " + target);

                    tempHost = remoteHost;
                    tempPort = remotePort;

                    SSLSocket remoteSocket;
                    String serverCN;
                    BigInteger serialno;
                    try {
                        //Lookup the "common name" field of the certificate from the remote server:
                        remoteSocket = (SSLSocket)
                                proxySSLEngine.getSocketFactory().createClientSocket(remoteHost, remotePort);

                        SSLSession session = remoteSocket.getSession();
                        Certificate[] servercerts = session.getPeerCertificates();
                        List mylist = new ArrayList();
                        for (int i = 0; i < servercerts.length; i++) {
                            mylist.add(servercerts[i]);
                        }
                        CertificateFactory cf = CertificateFactory.getInstance("X.509");
                        CertPath cp = cf.generateCertPath(mylist);
                        X509Certificate cert = (X509Certificate)cp.getCertificates().get(0);

                        serialno = cert.getSerialNumber();
                        LdapName ln = new LdapName(cert.getSubjectX500Principal().getName());

                        serverCN = ln.toString();

                    } catch (IOException ioe) {
                        ioe.printStackTrace();
                        sendClientResponse(localSocket.getOutputStream(), "504 Gateway Timeout", remoteHost, remotePort);
                        continue;
                    }

                    proxySSLEngine.setRemoteSocket(remoteSocket);

                    // Create new cert
                    ServerSocket localProxy = proxySSLEngine.createServerSocket(serverCN, serialno);

                    new Thread(proxySSLEngine, "HTTPS proxy SSL engine").start();

                    try {
                        Thread.sleep(10);
                    } catch (Exception ignore) {
                    }

                    final Socket sslProxySocket =
                            getSocketFactory().createClientSocket(
                                    getConnectionDetails().getLocalHost(),
                                    localProxy.getLocalPort());

                    // Threads to handle traffic
                    new Thread(new CopyStreamRunnable(
                            in, sslProxySocket.getOutputStream()),
                            "Copy to proxy engine for " + target).start();

                    final OutputStream out = localSocket.getOutputStream();

                    new Thread(new CopyStreamRunnable(sslProxySocket.getInputStream(), out),"Copy from proxy engine for " + target).start();

                    // Respond to client
                    sendClientResponse(out, "200 OK", remoteHost, remotePort);
                } else {
                    System.err.println(
                            "Failed to determine proxy destination from message:");
                    System.err.println(line);
                    sendClientResponse(localSocket.getOutputStream(), "501 Not Implemented", "localhost",
                            getConnectionDetails().getLocalPort());
                }
            } catch (InterruptedIOException e) {
                System.err.println(ACCEPT_TIMEOUT_MESSAGE);
                break;
            } catch (Exception e) {
                e.printStackTrace(System.err);
            }
        }
    }

    private void sendClientResponse(OutputStream out, String msg, String remoteHost, int remotePort) throws IOException {
        final StringBuffer response = new StringBuffer();
        response.append("HTTP/1.0 ").append(msg).append("\r\n");
        response.append("Host: " + remoteHost + ":" +
                remotePort + "\r\n");
        response.append("\r\n");
        out.write(response.toString().getBytes());
        out.flush();
    }

    /*
     * Used to funnel data between a client (e.g. a web browser) and a
     * remote SSLServer, that the client is making a request to
     *
     */
    private class ProxySSLEngine extends ProxyEngine {
        Socket remoteSocket = null;
        int timeout = 0;

        ProxySSLEngine(SSLSocketFactory socketFactory,
                       ProxyDataFilter requestFilter,
                       ProxyDataFilter responseFilter)
                throws IOException {
            super(socketFactory, requestFilter, responseFilter,
                    new ConnectionDetails(HTTPSProxyEngine.this.
                            getConnectionDetails().getLocalHost(),
                            0, "", -1, true),
                    0);
        }

        public final void setRemoteSocket(Socket s) {
            this.remoteSocket = s;
        }

        public final ServerSocket createServerSocket(String remoteServerCN, BigInteger serialno) throws IOException, java.security.GeneralSecurityException, Exception {
            SSLSocketFactory ssf = new SSLSocketFactory(remoteServerCN, serialno);
            m_serverSocket = ssf.createServerSocket("localhost", 0, timeout);
            return m_serverSocket;
        }


        /*
         * localSocket.get[In|Out]putStream() is data that's (indirectly)
         * being read from / written to the client
         *
         * tempHost is the remote SSL Server
         */
        public void run() {
            try {
                final Socket localSocket = this.getServerSocket().accept();

                System.err.println("New proxy proxy connection to " +
                        tempHost + ":" + tempPort);

                this.launchThreadPair(localSocket, remoteSocket,
                        localSocket.getInputStream(),
                        localSocket.getOutputStream(),
                        tempHost, tempPort);
            } catch (IOException e) {
                e.printStackTrace(System.err);
            }
        }
    }

}
