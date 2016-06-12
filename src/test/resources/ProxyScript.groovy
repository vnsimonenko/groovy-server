package ukrpay.test

import java.nio.channels.SocketChannel

try {
    return ServerHandler.execute(socketChannel, data);
} catch (Exception ex) {
    throw new RuntimeException("Internal exception", ex);
}


class ServerHandler {
    public static byte[] execute(SocketChannel socketChannel, byte[] data) {
        InetSocketAddress local = socketChannel.getLocalAddress();
        InetSocketAddress remote = socketChannel.getRemoteAddress();
        String answer = String.format(
                "data: %s," +
                        " local address: %s," +
                        " remote address: %s\n",
                new String(data, "UTF-8").trim(),
                local.getHostName() + ":" + local.getPort(),
                remote.getHostName() + ":" + remote.getPort());
        return answer.getBytes("UTF-8");
    }
}

