import java.io.*;
import java.net.*;
import java.util.concurrent.*;

/**
 * ArCHie Analyzer — Embedded Java Proxy
 * Tunnels HTTPS traffic through a local Java process to help work around
 * network-level URL restrictions in corporate or managed environments.
 * Note: effectiveness depends on the specific restrictions in place.
 *
 * Performance tuning applied:
 *   - TCP_NODELAY = true        (reduces latency)
 *   - SO_RCVBUF / SO_SNDBUF    (256 KB — full throughput, no TCP throttle)
 *   - SO_REUSEADDR = true       (no port-in-use error on restart)
 *   - 64 KB data buffer         (fewer syscalls, lower CPU usage)
 *   - CachedThreadPool          (no thread cap, handles parallel API calls)
 */
public class SimpleProxy {

    private static final int PORT     = 8888;
    private static final int BUF_SIZE = 65536;   // 64 KB
    private static final int SOCK_BUF = 262144;  // 256 KB

    public static void main(String[] args) throws IOException {
        ExecutorService pool = Executors.newCachedThreadPool();

        try (ServerSocket server = new ServerSocket()) {
            server.setReuseAddress(true);
            server.setReceiveBufferSize(SOCK_BUF);
            server.bind(new InetSocketAddress(PORT));

            System.out.println("[ArCHie Proxy] Listening on port " + PORT);

            // Gracefully shut down pool on CTRL+C / SIGTERM
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                pool.shutdownNow();
                System.out.println("[ArCHie Proxy] Shutdown complete.");
            }));

            while (true) {
                Socket client = server.accept();
                pool.submit(() -> handle(client));
            }
        }
    }

    private static void handle(Socket client) {
        try {
            tune(client);
            InputStream  clientIn  = client.getInputStream();
            OutputStream clientOut = client.getOutputStream();
            BufferedReader reader  = new BufferedReader(new InputStreamReader(clientIn));

            String requestLine = reader.readLine();
            if (requestLine == null || !requestLine.startsWith("CONNECT")) {
                client.close();
                return;
            }

            // Parse "CONNECT host:port HTTP/1.1"
            String[] parts    = requestLine.split(" ");
            String   hostPort = parts[1];
            String   host     = hostPort.split(":")[0];
            int      port     = Integer.parseInt(hostPort.split(":")[1]);

            // Connect to target host and relay traffic through the tunnel
            Socket remote = new Socket();
            tune(remote);
            remote.connect(new InetSocketAddress(host, port), 10000);

            // Handshake: tell client tunnel is open
            clientOut.write("HTTP/1.1 200 Connection Established\r\n\r\n".getBytes());
            clientOut.flush();

            // Bidirectional pipe
            CompletableFuture.runAsync(() -> pipe(client, remote));
            pipe(remote, client);

        } catch (Exception e) {
            // Silent fail — broken connections are dropped cleanly
        }
    }

    /** Apply all socket performance tuning in one place. */
    private static void tune(Socket s) throws SocketException {
        s.setTcpNoDelay(true);            // Disable Nagle — send immediately
        s.setReceiveBufferSize(SOCK_BUF); // 256 KB receive buffer
        s.setSendBufferSize(SOCK_BUF);    // 256 KB send buffer
        s.setKeepAlive(true);
    }

    /** Copy bytes from src to dest until EOF or error. */
    private static void pipe(Socket src, Socket dest) {
        try {
            InputStream  in  = src.getInputStream();
            OutputStream out = dest.getOutputStream();
            byte[] buf = new byte[BUF_SIZE];
            int len;
            while ((len = in.read(buf)) != -1) {
                out.write(buf, 0, len);
                out.flush();
            }
        } catch (Exception e) {
            try { src.close();  } catch (IOException ignored) {}
            try { dest.close(); } catch (IOException ignored) {}
        }
    }
}
