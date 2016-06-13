package kilimandjaro;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManagerFactory;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.SocketChannel;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;

/**
 * SSL implementation {@link SocketHandler}
 */
public class SSLSocketHandler implements SocketHandler {
    final static Logger logger = LoggerFactory.getLogger(Server.class);

    private String keyStoreFilePath;
    private String trustStoreFilePath;
    private String password;
    private SSLEngine sslEngine;
    private ByteBuffer appData;
    private ByteBuffer netData;
    private ByteBuffer peerAppData;
    private ByteBuffer peerNetData;
    private static ThreadPoolExecutor executor =
            (ThreadPoolExecutor) Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors());

    /**
     * the path to the private key file
     *
     * @param keystoreFilePath
     */
    public void setKeystoreFilePath(String keystoreFilePath) {
        this.keyStoreFilePath = keystoreFilePath;
    }

    /**
     * the path to the trusted key file
     *
     * @param trustStoreFilePath
     */
    public void setTrustStoreFilePath(String trustStoreFilePath) {
        this.trustStoreFilePath = trustStoreFilePath;
    }

    /**
     * private key password
     *
     * @param password
     */
    public void setPassword(String password) {
        this.password = password;
    }

    @Override
    public boolean accept(SocketChannel socket) throws IOException {
        try {
            sslEngine = createSSLEngine();
            createBuffers(sslEngine);
            sslEngine.beginHandshake();
            return doHandshake(socket);
        } catch (Exception ex) {
            throw new IOException(ex);
        }
    }

    @Override
    public byte[] read(SocketChannel socketChannel) throws IOException {
        return readAndDecode(socketChannel);
    }

    @Override
    public void write(SocketChannel socketChannel, byte[] data) throws IOException {
        if (data != null) {
            //if the data size exceeds the buffer size then increases its
            if (data.length > appData.capacity()) {
                appData = ByteBuffer.allocate(data.length);
            }
            try {
                writeAndEncode(socketChannel, data);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    @Override
    public void close(SocketChannel socketChannel) throws IOException {
        shuttingDownSSLConnection(socketChannel);
    }

    private void createBuffers(SSLEngine sslEngine) {
        SSLSession session = sslEngine.getSession();
        appData = ByteBuffer.allocate(session.getApplicationBufferSize());
        netData = ByteBuffer.allocate(session.getPacketBufferSize());
        peerAppData = ByteBuffer.allocate(session.getApplicationBufferSize());
        peerNetData = ByteBuffer.allocate(session.getPacketBufferSize());
    }

    private SSLEngine createSSLEngine() throws IOException, KeyStoreException,
            CertificateException, NoSuchAlgorithmException,
            UnrecoverableKeyException, KeyManagementException {
        KeyStore ks = KeyStore.getInstance("JKS");
        KeyStore ts = KeyStore.getInstance("JKS");

        char[] passphrase = password.toCharArray();

        try (InputStream keyIn = new FileInputStream(keyStoreFilePath)) {
            try (InputStream trustIn = new FileInputStream(trustStoreFilePath)) {
                ks.load(keyIn, passphrase);
                ts.load(trustIn, passphrase);
            }
        }

        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(ks, passphrase);

        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        tmf.init(ts);

        SSLContext sslCtx = SSLContext.getInstance("TLS");
        sslCtx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        SSLEngine sslEngine = sslCtx.createSSLEngine();
        sslEngine.setUseClientMode(false);
        return sslEngine;
    }

    /**
     * Processing handshake
     *
     * @param socketChannel
     * @return true - if successed
     * @throws Exception
     */
    private boolean doHandshake(SocketChannel socketChannel) throws Exception {
        appData.clear();
        peerAppData.clear();
        netData.clear();
        peerNetData.clear();

        SSLEngineResult.HandshakeStatus handStatus = sslEngine.getHandshakeStatus();

        while (handStatus != SSLEngineResult.HandshakeStatus.FINISHED &&
                handStatus != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {

            switch (handStatus) {

                case NEED_UNWRAP:
                    if (socketChannel.read(peerNetData) < 0) {
                        if (sslEngine.isInboundDone() && sslEngine.isOutboundDone()) {
                            throw new SSLException("Connection was closed");
                        }
                        //sslEngine.closeInbound();
                        sslEngine.closeOutbound();
                        handStatus = sslEngine.getHandshakeStatus();
                        break;
                    }

                    peerNetData.flip();
                    SSLEngineResult res = sslEngine.unwrap(peerNetData, peerAppData);
                    peerNetData.compact();
                    handStatus = res.getHandshakeStatus();

                    switch (res.getStatus()) {
                        case OK:
                            peerNetData.mark();
                            break;
                        case BUFFER_UNDERFLOW:
                            peerNetData.clear();
                            break;
                        case BUFFER_OVERFLOW:
                            peerAppData = handleBufferOverlow(peerAppData);
                            break;
                        case CLOSED:
                            throw new IOException("Connection was closed");
                    }
                    break;

                case NEED_WRAP:
                    netData.clear();
                    res = sslEngine.wrap(appData, netData);
                    handStatus = res.getHandshakeStatus();
                    switch (res.getStatus()) {
                        case OK:
                            netData.flip();
                            while (netData.hasRemaining()) {
                                socketChannel.write(netData);
                            }
                            break;
                        case BUFFER_UNDERFLOW:
                            break;
                        case BUFFER_OVERFLOW:
                            break;
                        case CLOSED:
                            throw new IOException("Connection was closed");
                    }
                    break;

                case NEED_TASK:
                    Runnable task;
                    while ((task = sslEngine.getDelegatedTask()) != null) {
                        executor.execute(task);
                    }
                    handStatus = sslEngine.getHandshakeStatus();
                    break;
                case FINISHED:
                    break;
                case NOT_HANDSHAKING:
                    break;
                default:
                    throw new IllegalStateException("Invalid SSL status: " + handStatus);
            }
        }
        return handStatus == SSLEngineResult.HandshakeStatus.FINISHED;
    }

    /**
     * It increases the size of the buffer to decode the input data
     *
     * @param appBuffer
     * @return a new buffer or cleaned
     */
    private ByteBuffer handleBufferOverlow(ByteBuffer appBuffer) {
        int size = sslEngine.getSession().getApplicationBufferSize();
        if (size > appBuffer.capacity()) {
            appBuffer = ByteBuffer.allocate(size);
        } else {
            appBuffer.clear();
        }
        return appBuffer;
    }

    /**
     * It increases the size of the buffer for the receiving encode data
     *
     * @param netBuffer
     * @return a new buffer or cleaned
     */
    private ByteBuffer handleBufferUnderflow(ByteBuffer netBuffer) {
        int size = sslEngine.getSession().getPacketBufferSize();
        if (size > netBuffer.capacity()) {
            ByteBuffer cloneBuffer = ByteBuffer.allocate(size);
            netBuffer.flip();
            cloneBuffer.put(netBuffer);
            return cloneBuffer;
        } else {
            //the method compact does not make sense to call
            //because a peer byte buffer is a shared between the different sockets
            //if one socket: for later reading the previous socket must be called the method compact
            return (ByteBuffer) netBuffer.clear();
        }
    }

    /**
     * Reading and decoding of the input data
     *
     * @param socketChannel
     * @return decoded array of bytes
     * @throws IOException
     */
    private byte[] readAndDecode(SocketChannel socketChannel) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        peerNetData.clear();
        int bytesRead = socketChannel.read(peerNetData);
        if (bytesRead > 0) {
            peerNetData.flip();
            while (peerNetData.hasRemaining()) {
                peerAppData.clear();
                SSLEngineResult result = sslEngine.unwrap(peerNetData, peerAppData);
                switch (result.getStatus()) {
                    case OK:
                        peerAppData.flip();
                        bos.write(peerAppData.array());
                        break;
                    case BUFFER_OVERFLOW:
                        peerAppData = handleBufferOverlow(peerAppData);
                        break;
                    case BUFFER_UNDERFLOW:
                        peerNetData = handleBufferUnderflow(peerNetData);
                        break;
                    case CLOSED:
                        logger.info("Received" + result.getStatus() + "during reading");
                        throw new ClosedChannelException();
                    default:
                        throw new IllegalStateException("Invalid SSL status: " + result.getStatus());
                }
            }
        }
        return bytesRead == -1 && bos.size() == 0 ? null : bos.toByteArray();
    }

    /**
     * encoding and writing byte array to the client
     *
     * @param socketChannel
     * @param data          - encode array bytes to client
     * @throws IOException
     */
    public void writeAndEncode(SocketChannel socketChannel, byte[] data) throws IOException {
        appData.clear();
        appData.put(data);
        appData.flip();
        while (appData.hasRemaining()) {
            netData.clear();
            SSLEngineResult result = sslEngine.wrap(appData, netData);
            switch (result.getStatus()) {
                case OK:
                    netData.flip();
                    int writingNumber = 0;
                    while (netData.hasRemaining()) {
                        writingNumber = socketChannel.write(netData);
                    }
                    System.out.println("Writing number = " + writingNumber);
                    break;
                case BUFFER_OVERFLOW:
                case BUFFER_UNDERFLOW:
                case CLOSED:
                    logger.info("Received" + result.getStatus() + "during writing");
                    throw new ClosedChannelException();
                default:
                    throw new IllegalStateException("Invalid SSL status: " + result.getStatus());
            }
        }
    }

    /**
     * to close channel
     *
     * @param channel
     * @throws IOException
     */
    private void shuttingDownSSLConnection(SocketChannel channel) throws IOException {
        sslEngine.closeOutbound();
        appData.clear();
        netData.clear();
        while (!sslEngine.isOutboundDone()) {
            SSLEngineResult res = sslEngine.wrap(appData, netData);
            if (res.getStatus() != SSLEngineResult.Status.CLOSED) {
                while (netData.hasRemaining()) {
                    channel.write(netData);
                    netData.compact();
                }
            }
        }
        channel.close();
    }
}
