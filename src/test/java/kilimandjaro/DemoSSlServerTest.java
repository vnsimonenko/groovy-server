package kilimandjaro;

import org.junit.Assert;
import org.junit.Test;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.InetSocketAddress;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

public class DemoSSlServerTest {

    @Test
    public void test() throws Exception {
        String scriptPath = DemoSSlServerTest.class.getClassLoader().getResource("ProxyScript.groovy").getFile();
        String keystorePath = DemoSSlServerTest.class.getClassLoader().getResource("keystore.jks").getFile();
        String truststorePath = DemoSSlServerTest.class.getClassLoader().getResource("truststore.jks").getFile();
        Thread thread = new Thread(() -> {
            try (Server<SSLSocketHandler> server = new Server<>(new SSLSocketHandler(), scriptPath, 500)) {
                server.getSocketHandler().setKeystoreFilePath(keystorePath);
                server.getSocketHandler().setTrustStoreFilePath(truststorePath);
                server.getSocketHandler().setPassword("qwerty");
                server.start();
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
        thread.setDaemon(true);
        thread.start();
        Thread.sleep(100);

        SSLContext sslContext = createTrustAllSSLContext();
        SSLSocketFactory factory = sslContext.getSocketFactory();
        SSLSocket socket =
                (SSLSocket) factory.createSocket("localhost", 8443);

        socket.startHandshake();

        PrintWriter out = new PrintWriter(
                new BufferedWriter(
                        new OutputStreamWriter(
                                socket.getOutputStream())));

        out.print("test1");
        out.flush();

        if (out.checkError()) {
            Assert.fail();
        }

        BufferedReader in = new BufferedReader(
                new InputStreamReader(
                        socket.getInputStream()));

        String inputLine;
        while ((inputLine = in.readLine()) != null) {
            System.out.println(inputLine);
            break;
        }

        Assert.assertEquals(expectAnswer(socket, "test1"), inputLine);

        out.print("test2");
        out.flush();

        while ((inputLine = in.readLine()) != null) {
            System.out.println(inputLine);
            break;
        }

        Assert.assertEquals(expectAnswer(socket, "test2"), inputLine);

        in.close();
        out.close();
        socket.close();
    }

    private String expectAnswer(SSLSocket socket, String data) {
        InetSocketAddress localAddress = (InetSocketAddress) socket.getLocalSocketAddress();
        InetSocketAddress remoteAddress = (InetSocketAddress) socket.getRemoteSocketAddress();
        return String.format(
                "data: %s," +
                        " local address: %s," +
                        " remote address: %s",
                data,
                remoteAddress.getHostName() + ":" + remoteAddress.getPort(),
                localAddress.getHostName() + ":" + localAddress.getPort());
    }

    public static SSLContext createTrustAllSSLContext() throws Exception {
        TrustManager[] byPassTrustManagers = new TrustManager[]{
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }

                    public void checkClientTrusted(X509Certificate[] chain, String authType) {
                    }

                    public void checkServerTrusted(X509Certificate[] chain, String authType) {
                    }
                }
        };
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, byPassTrustManagers, new SecureRandom());
        return sslContext;
    }
}
