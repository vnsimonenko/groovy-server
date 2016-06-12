package kilimandjaro;

import java.io.IOException;
import java.nio.channels.SocketChannel;

/**
 * The strategy of reading, write access for non-blocking sockets
 */
public interface SocketHandler {

    /**
     * Establishing a connection with the client
     *
     * @param socketChannel
     * @return boolean true - if the client established a connection and got a socket, false otherwise
     * @throws IOException
     */
    boolean accept(SocketChannel socketChannel) throws IOException;

    /**
     * Reading data from socket
     *
     * @param socketChannel - reading channel
     * @return an array of bytes was transferred to the client
     * @throws IOException
     */
    byte[] read(SocketChannel socketChannel) throws IOException;

    /**
     * Write an array of bytes received by the client
     *
     * @param socketChannel - recording channel
     * @param data          - byte array was generated for the client as a result of its request
     * @throws IOException
     */
    void write(SocketChannel socketChannel, byte[] data) throws IOException;

    /**
     * Closing the connection with client
     *
     * @param socketChannel
     * @throws IOException
     */
    void close(SocketChannel socketChannel) throws IOException;
}
