//Based on SnifferSSLSocketFactory.java from The Grinder distribution.
// The Grinder distribution is available at http://grinder.sourceforge.net/

import sun.security.x509.*;

import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;
import javax.net.ssl.*;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Date;


/**
 * SSLSocketFactory is used to create SSL sockets.
 *
 * This is needed because the javax.net.ssl socket factory classes don't
 * allow creation of factories with custom parameters.
 *
 */
public final class SSLSocketFactory implements MITMSocketFactory
{
    final ServerSocketFactory serverSocketFactory;
    final SocketFactory clientSocketFactory;
    final SSLContext sslContext;

    public KeyStore ks = null;

	/* Factory for all other sockets, static cert */
    public SSLSocketFactory()
	throws IOException,GeneralSecurityException
    {
		sslContext = SSLContext.getInstance("SSL");

		final KeyManagerFactory keyManagerFactory =
			KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());

		final String keyStoreFile = System.getProperty(JSSEConstants.KEYSTORE_PROPERTY);
		final char[] keyStorePassword = System.getProperty(JSSEConstants.KEYSTORE_PASSWORD_PROPERTY, "").toCharArray();
		final String keyStoreType = System.getProperty(JSSEConstants.KEYSTORE_TYPE_PROPERTY, "jks");

		final KeyStore keyStore;

		if (keyStoreFile == null) {
			keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
			keyStore.load(null,null);
			this.ks = keyStore;
		} else {
			keyStore = KeyStore.getInstance(keyStoreType);
			keyStore.load(new FileInputStream(keyStoreFile), keyStorePassword);

			this.ks = keyStore;
		}

		keyManagerFactory.init(keyStore, keyStorePassword);

		sslContext.init(keyManagerFactory.getKeyManagers(),
				  new TrustManager[] { new TrustSettings() },
				  null);

		clientSocketFactory = sslContext.getSocketFactory();
		serverSocketFactory = sslContext.getServerSocketFactory();
    }

    public SSLSocketFactory(String remoteCN, BigInteger serialno)
	throws IOException,GeneralSecurityException, Exception {

        sslContext = SSLContext.getInstance("SSL");

        final KeyManagerFactory keyManagerFactory =
                KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());

        final String keyStoreFile = System.getProperty(JSSEConstants.KEYSTORE_PROPERTY);
        final char[] keyStorePassword = System.getProperty(JSSEConstants.KEYSTORE_PASSWORD_PROPERTY, "").toCharArray();
        final String keyStoreType = System.getProperty(JSSEConstants.KEYSTORE_TYPE_PROPERTY, "jks");

        final KeyStore keyStore;

        if (keyStoreFile != null) {
            keyStore = KeyStore.getInstance(keyStoreType);
            keyStore.load(new FileInputStream(keyStoreFile), keyStorePassword);

            this.ks = keyStore;
        } else {
            keyStore = null;
        }

        keyManagerFactory.init(keyStore, keyStorePassword);

        sslContext.init(keyManagerFactory.getKeyManagers(),
                new TrustManager[] { new TrustSettings() },
                null);

        clientSocketFactory = sslContext.getSocketFactory();
        serverSocketFactory = sslContext.getServerSocketFactory();

        //New certificate creation
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
        keyGen.initialize(1024, random);
        KeyPair keyPair = keyGen.generateKeyPair();

        PrivateKey privateKey = keyPair.getPrivate();
        X509CertInfo info = new X509CertInfo();
        Date from = new Date();
        Date to = new Date(from.getTime() + 365 * 86400000l);
        CertificateValidity interval = new CertificateValidity(from, to);

        X500Name owner = new X500Name(remoteCN);
        info.set(X509CertInfo.VALIDITY, interval);
        info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(serialno));
        info.set(X509CertInfo.SUBJECT, owner);
        info.set(X509CertInfo.ISSUER, owner);
        info.set(X509CertInfo.KEY, new CertificateX509Key(keyPair.getPublic()));
        info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
        AlgorithmId algo = new AlgorithmId(AlgorithmId.md5WithRSAEncryption_oid);
        info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algo));

        //Certificate signing
        X509CertImpl cert = new X509CertImpl(info);
        cert.sign(privateKey, "SHA1withRSA");

        algo = (AlgorithmId)cert.get(X509CertImpl.SIG_ALG);
        info.set(CertificateAlgorithmId.NAME + "." + CertificateAlgorithmId.ALGORITHM, algo);

        cert = new X509CertImpl(info);
        cert.sign((PrivateKey) ks.getKey("mykey", "password".toCharArray()), "SHA1withRSA");
        ks.setCertificateEntry(remoteCN,cert);
	}

    public final ServerSocket createServerSocket(String localHost,int localPort,int timeout)throws IOException {
		final SSLServerSocket socket =
			(SSLServerSocket) serverSocketFactory.createServerSocket(
			localPort, 50, InetAddress.getByName(localHost));

		socket.setEnabledProtocols(new String[]{"TLSv1","TLSv1.1","TLSv1.2","SSLv2Hello"});
		socket.setSoTimeout(timeout);

		socket.setEnabledCipherSuites(socket.getSupportedCipherSuites());

		System.out.print("Server enabled protocols: ");
		int arrayLength = socket.getEnabledProtocols().length;
		int i=0;
		for(i=0;i<arrayLength;i++){
			System.out.print(socket.getEnabledProtocols()[i] + " ");
		}
		return socket;
    }

    public final Socket createClientSocket(String remoteHost, int remotePort)throws IOException{
		final SSLSocket socket =
			(SSLSocket) clientSocketFactory.createSocket(remoteHost,
								  remotePort);

		System.out.print("Client enabled protocols: ");
		socket.setEnabledProtocols(new String[]{"TLSv1","TLSv1.1","TLSv1.2","SSLv2Hello"});
		socket.setEnabledCipherSuites(socket.getSupportedCipherSuites());

		int arrayLength = socket.getEnabledProtocols().length;
		int i=0;
		for(i=0;i<arrayLength;i++){
			System.out.print(socket.getEnabledProtocols()[i] + " ");
		}

		socket.startHandshake();
		return socket;
    }

    /*
     * Overwriting interface methods to prevent checking if the cert is trusted
     */
    private static class TrustSettings implements X509TrustManager
    {
		public void checkClientTrusted(X509Certificate[] chain,
				       String authenticationType) {
		}
		public X509Certificate[] getAcceptedIssuers()
		{
			return null;
		}

		public void checkServerTrusted(X509Certificate[] chain,
				       String authenticationType) {
		}
    }
}
    
