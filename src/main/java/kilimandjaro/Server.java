package kilimandjaro;

import groovy.lang.Binding;
import groovy.lang.GroovyShell;
import groovy.lang.Script;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.FileTime;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.atomic.AtomicReference;

/**
 * ProxyServer - proxy server with non-blocking sockets.
 * Query processing is performed through GroovyScript,
 * Which can be dynamically updated.
 * Default sampling time on a change (modification) of script is 5 seconds.
 *
 * @param <T> T type of handler for access, read, write by non-blocking sockets.
 */
public class Server<T extends SocketHandler> implements AutoCloseable {
    private String host = "localhost";
    private int port = 8443;
    private int timeoutForSelector = 1000;
    private int refreshPeriodOfGroovyScript = 5000;
    private LinkedBlockingQueue readingQueue;
    private Map<String, LinkedBlockingQueue> writtingQueueMap = new ConcurrentHashMap<>();
    private ThreadPoolExecutor executor =
            (ThreadPoolExecutor) Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors());
    private T socketHandler;
    private String groovyScriptPath;
    private AtomicReference<String> groovyScript = new AtomicReference<>();
    private FileTime lastLastModifiedTimeForGroovy;
    private boolean isActive; //признак завершения прослушивания сокетов клиентов

    /**
     * Host of server
     *
     * @param host - default is localhost
     */
    private void setServerHost(String host) {
        this.host = host;
    }

    /**
     * Listening server port
     *
     * @param port - default is 8443
     */
    private void setServerPort(int port) {
        this.port = port;
    }

    /**
     * The delay in obtaining the client's listening socket
     *
     * @param timeoutForSelector in milliseconds
     */
    public void setTimeoutForSelector(int timeoutForSelector) {
        this.timeoutForSelector = timeoutForSelector;
    }

    /**
     * The period of the survey last modification groovy script
     *
     * @param refreshPeriodOfGroovyScript in milliseconds
     */
    public void setRefreshPeriodOfGroovyScript(int refreshPeriodOfGroovyScript) {
        this.refreshPeriodOfGroovyScript = refreshPeriodOfGroovyScript;
    }

    /**
     * Link to access, reading, writing the handler for non-blocking sockets.
     *
     * @return instance of a socket handler
     */
    public T getSocketHandler() {
        return socketHandler;
    }

    /**
     * Constructor
     *
     * @param socketHandler          - see @{@link SocketHandler}
     * @param groovyScriptPath       - Controller processing client requests. Generates a byte array output to the client.
     * @param readingCleintQueueSize - the size of the queue to the requesting client.
     */
    public Server(T socketHandler, String groovyScriptPath, int readingCleintQueueSize) {
        this.socketHandler = socketHandler;
        this.groovyScriptPath = groovyScriptPath;
        readingQueue = new LinkedBlockingQueue(readingCleintQueueSize);
    }

    /**
     * start
     *
     * @throws IOException
     */
    public void start() throws IOException {
        ServerSocketChannel channel = ServerSocketChannel.open();
        channel.bind(new InetSocketAddress(host, port));
        channel.configureBlocking(false);
        Selector selector = Selector.open();

        SelectionKey selectionKey = channel.register(selector, SelectionKey.OP_ACCEPT);

        isActive = true;

        /*
            Specifies the number of client processors equal to the number of virtual / real threads.
            The input data is transmitted to groovy script, which executes business logic and generates data to the client.
            The output array of bytes will be formed to client by the groovy script.
            The key, or ID see getAddressKey.
         */
        for (int i = Runtime.getRuntime().availableProcessors(); i > 0; i--) {
            executor.execute(() -> {
                while (!Thread.interrupted() && isActive) {
                    try {
                        SelectionKey key = (SelectionKey) readingQueue.take();
                        SocketChannel socketChannel = (SocketChannel) key.channel();
                        String address = getAddressKey((InetSocketAddress) socketChannel.getRemoteAddress());
                        LinkedBlockingQueue writingQueue = writtingQueueMap.get(address);
                        if (writingQueue == null) {
                            synchronized (writtingQueueMap) {
                                if (!writtingQueueMap.containsKey(address)) {
                                    writingQueue = new LinkedBlockingQueue(1000);
                                    writtingQueueMap.put(address, writingQueue);
                                } else {
                                    writingQueue = writtingQueueMap.get(address);
                                }
                            }
                        }
                        byte[] data = (byte[]) key.attachment();

                        Binding binding = new Binding();
                        binding.setVariable("data", data);
                        binding.setVariable("socketChannel", socketChannel);
                        GroovyShell shell = new GroovyShell(binding);
                        Script script = shell.parse(groovyScript.get());
                        script.setBinding(binding);
                        byte[] result = (byte[]) script.run();
                        writingQueue.put(result);
                    } catch (InterruptedException | IOException ex) {
                        ex.printStackTrace();
                    }
                }
            });
        }

        refreshGroovyScript();
        //timer update script
        Timer timer = new Timer();
        timer.schedule(new TimerTask() {
            @Override
            public void run() {
                try {
                    refreshGroovyScript();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }, refreshPeriodOfGroovyScript, refreshPeriodOfGroovyScript);

        while (!Thread.interrupted()) {
            while (selectionKey.selector().select(timeoutForSelector) > 0) {
                Set readyKeys = selector.selectedKeys();
                Iterator it = readyKeys.iterator();
                while (it.hasNext()) {
                    SelectionKey key = (SelectionKey) it.next();
                    it.remove();
                    try {
                        if (key.isAcceptable()) {
                            ServerSocketChannel ssc = (ServerSocketChannel) key.channel();
                            SocketChannel socket = ssc.accept();
                            socket.configureBlocking(false);
                            if (socketHandler.accept(socket)) {
                                socket.register(selector, SelectionKey.OP_READ | SelectionKey.OP_WRITE);
                            }
                        }
                        if (key.isReadable()) {
                            byte[] bytes = socketHandler.read((SocketChannel) key.channel());
                            if (bytes != null && bytes.length > 0) {
                                key.attach(bytes);
                                readingQueue.put(key);
                            } else if (bytes == null) {
                                continue;
                            }
                        }
                        if (key.isWritable()) {
                            SocketChannel socketChannel = ((SocketChannel) key.channel());
                            String address = getAddressKey((InetSocketAddress) socketChannel.getRemoteAddress());
                            LinkedBlockingQueue writtingQueue = writtingQueueMap.get(address);
                            byte[] data = writtingQueue == null ? null : (byte[]) writtingQueue.poll();
                            if (data != null) {
                                socketHandler.write(socketChannel, data);
                            }
                        }
                    } catch (Exception ex) {
                        ex.printStackTrace();
                    }
                }
            }
        }
    }

    /**
     * @return String groovyScript
     * @throws IOException, {@link NullPointerException}
     */
    private void refreshGroovyScript() throws IOException {
        Path path = Paths.get(groovyScriptPath);
        if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
            throw new NullPointerException("not found groovy script");
        }
        FileTime ft = Files.getLastModifiedTime(path, LinkOption.NOFOLLOW_LINKS);
        if (lastLastModifiedTimeForGroovy == null || ft.compareTo(lastLastModifiedTimeForGroovy) != 0) {
            lastLastModifiedTimeForGroovy = ft;
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            long readBytes = Files.copy(path, out);
            if (readBytes != out.size()) {
                throw new IOException("reading size of file not equal in buffer");
            }
            groovyScript.set(new String(out.toByteArray(), "UTF-8"));
        }
    }

    /**
     * to close server
     *
     * @throws Exception
     */
    @Override
    public void close() throws Exception {
        isActive = false;
    }

    /**
     * key of client address
     *
     * @param address InetSocketAddress
     * @return String format: {host}:{port}
     */
    private String getAddressKey(InetSocketAddress address) {
        return address.getHostName() + ":" + address.getPort();
    }
}
