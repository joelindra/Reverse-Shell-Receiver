package burp.listener;

import javax.net.ssl.*;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.InetAddress;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Creates SSL/TLS Server Sockets for encrypted reverse shell listeners (PowerShell TLS, Ncat SSL, Socat OpenSSL)
 * and HTTPS Webhooks with a complete, self-contained 2048-bit RSA PKCS#12 certificate.
 */
public final class TlsSocketHelper {

    // Valid, complete self-signed 2048-bit RSA PKCS#12 Keystore (password: "password")
    private static final String EMBEDDED_KEYSTORE_B64 =
            "MIIKxAIBAzCCCm4GCSqGSIb3DQEHAaCCCl8EggpbMIIKVzCCBa4GCSqGSIb3DQEHAaCCBZ8EggWb" +
            "MIIFlzCCBZMGCyqGSIb3DQEMCgECoIIFQDCCBTwwZgYJKoZIhvcNAQUNMFkwOAYJKoZIhvcNAQUM" +
            "MCsEFPdsyS4amUj5AolWsOYRe2rpApKJAgInEAIBIDAMBggqhkiG9w0CCQUAMB0GCWCGSAFlAwQB" +
            "KgQQa9vcZHolnvFQGoBgzuXw2ASCBNBUHsYO7Jclntx9ij++y1q5+L1JvMm3aXsbGU8CQg9JxmES" +
            "GDqjbtYxdZXx5dZ4tHnHBl87NjDZ2ilg+EP+GUUeUM4qMQsyR1kF+5xSJ0BLQDNNn8REtueACyAd" +
            "sZLseaOwlhbkXn0mubn29h00U67LMgY1RPMhqWfxjMWl6gbkD4rQ9cWJ5v6nnMd04rCrCnSmS+RB" +
            "o1+fFmrqvWvPAppNMTvMq6m7/nkmJVl7/vNjp34TgUN7Wl64gThwDRr9cl2oaegC1Z7Ln8DjVg6U" +
            "8hPLdGk/sb3pGHCKVjuw4spG8q6htpLjYsXwNkHZZvVFps4VgohYq2zFB7q3lPUdQXhs4ZKGFOCp" +
            "dJURMvdpwtRFF6l4PPuM1ps5tVdU9kt9ZIKL2eFs9S5XRYRL+yyNiscN+gjxNKoJW3P3Um1WsOZe" +
            "B04QW7Z/FNY1fQnGbm9oTVOQdOl5CjvbQHwz8LCJriE4goMq3MXH3gDKwN+4U3Mt3QLhVcF9VEaO" +
            "2D0ZB8SgEfs7w+GHlYuVVbl4n1f+i83/fbQxFI3Ymkcfs16PvaDiWJxddmJibw3RlcwYAJCPf2vJ" +
            "9XdwVmWWRK5cCQv9y3Rh8KpOvVsXuJGJJE5lMRpiTMflUYKIHFnIQEJn3Q81cutafMDFx1BvkWj6" +
            "WSNjU63L6Og2kz7atN954CnPy8E14csAogPrf3Rtk0CUs6EoWXV23ccP5OtzSsJqzTU+nIQ+Up2N" +
            "j6FdaP1rcZeN9ITOSkrXzdwpU+KYeck+22oVJLVAuvHM5kUdVfNRjRJuVxYy8bJy7n6Kv9e7VLxH" +
            "MwLuednACS9D8er7eeHShuktfzPu/kediXxvYHCTg77UYtvQyGEpgvS3J2rDUqrtOnrc3kCsXTya" +
            "uYiw6woG/uBo5La/nWK/tA9ABBHIK/fZG5Q/AntHpQLuz1TyUzV05OJZ5UKj15SnRU8fg6rfjou+" +
            "9aMR+Ym6ohK3crdViqu5U9/FsMOtw40P6NPnQTkzIC81fdW6x24x/NHc7T0sZePwF8xeAOXRZUor" +
            "RnY3ZKGpsJ8b7UzYRw0CyFgSoarh7ZwSzzL+eyFlttNOz2nxbQ68JBA6WsoG3n4RIyBrUcC2SUEL" +
            "7Zwu9Kzzm7RcwMaaXiWa94a8D8hK4EQm+IUcSWZKaEHpPbU7FWgiLXyInNz6UfNYnSHEf1nJO2h8" +
            "EDeGmqq3ticwjyBFiRbTUVylFhfAqgA5LHHy2QIPL2CJHePUxgGWv2TfUmXRAP4GaFxCuYriSVRm" +
            "1PuXTUfWi5RVGFt3fR1rn21OaIq6+dp05uBXUi978XU+B7Ra/5KapmOa2KIClUQLuuut9+Cl/tHB" +
            "7ByapegnAaXBwa3o8ziKKMCnRdqabEKUIhB/EeKjPVTwGD4ekB79gn2TiX8/sXRd+WXCzu/Xuf2m" +
            "BOUijJj1tU0gdhcvUaqQ3r4pVQnmebCYgZX4KUHwXA8jjzd10kNt/42FdbrJRE7LQuY+cxK3EUD" +
            "RAxtUM2XeF55XnU2GGYySdMUffzlXM8U5G5uAKM5i+NN3r5piuNNNRD4g2M0duag6EUBVhFt1kek" +
            "ZQU4kUfjzvT3GUdvyEGnts9ZXbdnZ8/ySbWVAKn1JtpLrMKYxHoDgKDXEfc8UScYd30L1JyLuUzp" +
            "oXzFAMBsGCSqGSIb3DQEJFDEOHgwAcwBlAHIAdgBlAHIwIQYJKoZIhvcNAQkVMRQEElRpbWUgMTc4" +
            "NzIxNjYyMTE3MjCCBKEGCSqGSIb3DQEHBqCCBJIwggSOAgEAMIIEhwYJKoZIhvcNAQcBMGYGCSqG" +
            "SIb3DQEFDTBZMDgGCSqGSIb3DQEFDDArBBS6hL+Ms95bxBtmcDwLDPgz/v6+0QICJxACASAwDAYI" +
            "KoZIhvcNAgkFADAdBglghkgBZQMEASoEEMnfLwt7n0ZFZva7M5K8oUyAggQQhmIFaoHdBhnWIJAE" +
            "AVjDqt1ZP9MLyglUSA2oI76wDYVUbR7anjHF3Y5z1B4ds2+6hLLKzHMRTTnRoEVQHLGTVHZEUKod" +
            "q5en4K2+syuc2UxCn7ADPDiOjHJKbEwDJ8rRaX59An0TsqiZ80R6ptzhYrjkgY5AmqzBAi4ZD8/w" +
            "KByVQ4hjH513UngKMDYxJkaGQTne9lwED1KfaaAwMX/NvPs2K/qLEc60zn/kxcjUAdSAM0ZTewSm" +
            "ZdCALHyhTJY+AtosYP8cJR9CyY3aAAbknOBMFscUeCDQ4xZQ6Jq57Dxw3633Vmi4Ba/765IyB4dF" +
            "d4reOwC03dzv8VmohGdjotlzNYFMPZO4qzQLMn5hWx02O44wNEE9IZmtbf1JIeR2zXiFWA3ie3cR" +
            "2lTgTMNlyznXOd+4A4x7nWZ80j/8sMQKx9fqEIxR9mfIzhcYt9ITMGyTiH2b77a9t93qhYLcW5ow" +
            "Q2kR3DOPZeAElJNB6s9OvaSUu7v0DuYTU1MdzL6oT8zGmimyg6DZL7oRx5gzakeL5wWzDHcCDD/c" +
            "H0pUCP1w/BAVW+knglFvyq6mk+kHANofcKZux6xV5WMvd3IFq9rv5Mqa9SWjczzAcGh/MTu30a/5" +
            "Rwg4bW6hg7mltzNRwW1jzAu0oxVSHx5a7vAAh7guy1mdikexavgyf8FQdB62i2BDPxcHwfLPTuq6" +
            "eNROBEomyssbDlYf5I8e9mOrBm0nEdlQJL2cjrmrwgY3ZpBnu8DdBi5XgNqEqbWv+IFTbyDqWaPb" +
            "eeVCXPcluFliXBSXF1X7remO8F+Wwcvv1S8uL+M36KbURkh511bXamAgSC46ItMlnhsLWfKvdCNN" +
            "2sxpXc1jxB/2rWNbFJ1TjqHup3frgaIPSXmTZuvAg3fwWIqccgGlH5qEULg8d+8aiWWrMiyrm129" +
            "ffcYm95pCSberP3pSAZuSlA99CQ39ta+0dt/bxPAu6P6akUt+cmaSj9ZKymGoyMicE5ctigEIlOc" +
            "aiGtY+x5u4rih8B8GrHG3e2S8NCcUL0Perl980vd7HbnEAzmCAiS2Mavirqjtva5kRBKusI632DG" +
            "peXon9bezgrat1I57jegWibWMiymcpElE1DRyFJFKQ/LcuEzkimAOb6WCbUT4AbNHeEuXTFaFzxK" +
            "7sMnKP+buCN6rQr+9vWMPzFdJ8zhc2zJHJwAWOtoB0Blu1g7wHGDz40QKxZDvbjKh//HdJOYRSU3" +
            "uN9oSeTFGg+HAf+3hjwyknm8iTa1QOxtduSqK4qTrM9xyMW6rgRf4Ywqnbp0i72CY327GMhkStEy" +
            "kV2tzF8MhopC+MiSi4KNV6TxR8JrHEBRr5fyAEpGzJZxlxlnA9eS+JuqKNjbi/FQuPZNwaqAOZ/9" +
            "szMwTTAxMA0GCWCGSAFlAwQCAQUABCDpSpFrW7ZzjSmAVI6kpgkb+vQeDQLdZa3W1fye6x7qYwQU" +
            "ugutX29BFAf7PmPPzh11wjA3NJsCAicQ";

    private TlsSocketHelper() {}

    public static SSLServerSocket createTlsServerSocket(int port, int backlog, InetAddress bindAddr) throws Exception {
        SSLContext sslContext = createSslContext();
        SSLServerSocketFactory factory = sslContext.getServerSocketFactory();
        SSLServerSocket serverSocket = (SSLServerSocket) factory.createServerSocket(port, backlog, bindAddr);
        serverSocket.setNeedClientAuth(false);
        serverSocket.setWantClientAuth(false);
        return serverSocket;
    }

    public static SSLContext createSslContext() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        char[] password = "password".toCharArray();

        byte[] keyStoreBytes = Base64.getDecoder().decode(EMBEDDED_KEYSTORE_B64);
        try (InputStream is = new ByteArrayInputStream(keyStoreBytes)) {
            keyStore.load(is, password);
        }

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, password);

        // Trust all manager for test client handshake
        TrustManager[] trustAllCerts = new TrustManager[] {
                new X509TrustManager() {
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() { return null; }
                    public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) {}
                    public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) {}
                }
        };

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), trustAllCerts, new SecureRandom());
        return sslContext;
    }
}
