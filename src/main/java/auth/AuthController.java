package auth;

import org.apache.tomcat.util.http.fileupload.IOUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestMapping;
import sun.security.x509.X509CertImpl;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.bind.DatatypeConverter;
import java.io.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import static auth.GenerateKeys.PRIVATE_KEY;
import static auth.GenerateKeys.PUBLIC_KEY;

@RestController
public class AuthController {

    public static final String LOCATION = "http://localhost:8080/users/login.html";

    @RequestMapping("/abc/")
    public void index(@RequestParam(value = "type", required = false) String type, HttpServletRequest req, HttpServletResponse res) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException, NoSuchProviderException {

        String authValue = "";

        if ("rsa".equals(type)) {
            authValue = getRSAEncrypted();
        } else {
            authValue = getAESEncrypted();
        }

        //authValue = "ua+vmcsr4mcKS3wpt0TZ2vNaboXe53XpZ2+5WCFnKLZ8gQuak/ibyXa+V3bB9g44bo/e8WOzXq6NBqdFVIlxjMk+tiADnjQPaE5U12UMZWxp2g9Zz01mbYtKGjQ0/KEU7tfamH8xCI0Nry07CO7HAkhrtsFcdFIFQbI7Kv8IE42Xe4FQGLWzTFV5mzEh6tRFs3+xs9tngce0aPfUAUigW9CWjR9K8yYzeVzkG7yrt+bwjiAoUmKx05Vcj0RHcL9g3+FZ2jRmd1XttdA4TvgQs+Y7c1vJQnY9M8INdEZ5V9AmW/4JvnkIcJ0dRf7yI4awXHAwnVPd4gQKj0v0hIb87W2fzr5tSEmWDlX5a1VMURb5iZ+OJCzgfDky+EqqM8gnDVT4nmcIl9ymTXw6mgVyTRRT0DikCYlEfNqNpcGrKQhEopFTURItqWnl5B+Lj+OhDybhXKTRoS9lNN3xlA1TsHSLJYcXOh7L3UlYLm0gZOtyOip2AKwcGSIrP+VSD0EH0v5/od54r7GODSPtw6xKPrc4+yqgUixR8fHimTwJpVbbdUtVvviBBc65h60cg6W/jXSTZJaPKUyOx3xhKO6Ea7Y2GftNJOEbguuXJah10+NKdmvvi7UexicoYiaDx/AuBVTKPbetZDPsTbnXRGNNv8GW0ATJrIuKDTTTxlGh2wg=";

        //authValue = "W%60E%A1%E8%CC%9E%B4%8C%06D%DDp%7C%3C%8Fdr%C6v%FE%1A%B79%C7%83%92%7B%C2%A92%19%AE";

        res.addCookie(buildAuthCookie(authValue));

        System.out.println(authValue);

        res.sendRedirect(LOCATION);
        // return "<a href=\"\">here</a>";

    }

    public PublicKey loadPublicKey(byte[] key)
            throws IOException, GeneralSecurityException {
        PublicKey publicKey = null;
        try (InputStream is = new ByteArrayInputStream(key)) {

            BufferedReader br = new BufferedReader(new InputStreamReader(is));
            StringBuilder builder = new StringBuilder();
            boolean inKey = false;
            for (String line = br.readLine(); line != null; line = br.readLine()) {
                if (!inKey) {
                    if (line.startsWith("-----BEGIN ") &&
                            line.endsWith(" PUBLIC KEY-----")) {
                        inKey = true;
                    }
                    continue;
                } else {
                    if (line.startsWith("-----END ") &&
                            line.endsWith(" PUBLIC KEY-----")) {
                        inKey = false;
                        break;
                    }
                    builder.append(line);
                }
            }
            KeyFactory kf = KeyFactory.getInstance("RSA");
            /*
            byte[] encoded = DatatypeConverter.parseBase64Binary(builder.toString());
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            publicKey = kf.generatePublic(keySpec);
            */
            X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(Base64.getDecoder().decode(builder.toString()));
            publicKey = (RSAPublicKey) kf.generatePublic(keySpecX509);

        }
        return publicKey;
    }

    public PrivateKey loadPrivateKey(byte[] key)
            throws IOException, GeneralSecurityException {
        PrivateKey privateKey = null;
        try (InputStream is = new ByteArrayInputStream(key)) {

            BufferedReader br = new BufferedReader(new InputStreamReader(is));
            StringBuilder builder = new StringBuilder();
            boolean inKey = false;
            for (String line = br.readLine(); line != null; line = br.readLine()) {
                if (!inKey) {
                    if (line.startsWith("-----BEGIN ") &&
                            line.endsWith(" PRIVATE KEY-----")) {
                        inKey = true;
                    }
                    continue;
                } else {
                    if (line.startsWith("-----END ") &&
                            line.endsWith(" PRIVATE KEY-----")) {
                        inKey = false;
                        break;
                    }
                    builder.append(line);
                }
            }
            KeyFactory kf = KeyFactory.getInstance("RSA");
            byte[] encoded = DatatypeConverter.parseBase64Binary(builder.toString());
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
            privateKey = kf.generatePrivate(keySpec);

        }
        return privateKey;
    }

    private String getRSAEncrypted() throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, IOException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException {
        Security.addProvider(new BouncyCastleProvider());
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");

        PublicKey publicKey = null;
        PrivateKey privateKey = null;

        if (!new File("keys/keys.pem").exists()) {
            GenerateKeys gk = new GenerateKeys(1024);
            gk.createKeys();
            gk.writeToFile(PUBLIC_KEY, gk.getPublicKey().getEncoded());
            gk.writeToFile(PRIVATE_KEY, gk.getPrivateKey().getEncoded());
            StringBuffer sb = new StringBuffer("-----BEGIN PRIVATE KEY-----\n");
            sb.append(Base64.getMimeEncoder().encodeToString(gk.getPrivateKey().getEncoded()));
            sb.append("\n-----END PRIVATE KEY-----\n");
            sb.append("-----BEGIN PUBLIC KEY-----\n");
            sb.append(Base64.getMimeEncoder().encodeToString(gk.getPublicKey().getEncoded()));
            sb.append("\n-----END PUBLIC KEY-----");

            gk.writeToFile("keys/keys.pem", sb.toString().getBytes());
            privateKey = gk.getPrivateKey();
            publicKey = gk.getPublicKey();
        } else {
            byte[] content = Files.readAllBytes(new File("keys/keys.pem").toPath());
            try {
                privateKey = loadPrivateKey(content);
                publicKey = loadPublicKey(content);
            } catch (GeneralSecurityException e) {
                e.printStackTrace();
            }
        }
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        return getCookieEncryptedValue(null, cipher);

    }

    private String getAESEncrypted() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        SecureRandom secureRandom = new SecureRandom();

        byte[] iv = new byte[16];

        secureRandom.nextBytes(iv);

        // Test static iv
        // iv = "abcdefghijklmnop".getBytes();

        IvParameterSpec ivspec = new IvParameterSpec(iv);

        SecretKeySpec keySpec = new SecretKeySpec("abcdefghijklmnopponmlkjihgfedcba".getBytes(), "AES");

        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivspec);

        return getCookieEncryptedValue(iv, cipher);
    }

    private Cookie buildAuthCookie(String authValue) throws UnsupportedEncodingException, MalformedURLException {
        Cookie cookie = new Cookie("ANSWER_HUB_SSO", authValue);

        cookie.setPath("/");

        cookie.setMaxAge(129600); //With it or without, makes no difference.

        URL urlToRedirect = new URL(LOCATION);

        cookie.setDomain(urlToRedirect.getHost());//With it or without, makes no difference.
        return cookie;
    }

    private String getCookieEncryptedValue(byte[] iv, Cipher cipher) throws IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
        StringBuffer result = new StringBuffer();
        if (null != iv) {
            result.append(Base64.getEncoder().encodeToString(iv));
        }

        result.append(Base64.getEncoder().encodeToString(
                cipher.doFinal("{\"userId\":\"ssaa27226327\",\"userName\":\"Pepe Trueno\",\"email\":\"pedro.zuppelli+08@gmail.com\"}".getBytes("UTF-8"))));

        return result.toString();
    }
}

// W%60E%A1%E8%CC%9E%B4%8C%06D%DDp%7C%3C%8Fdr%C6v%FE%1A%B79%C7%83%92%7B%C2%A92%19%AE,'9%A5%ADp8d%CC%1F%07%03%F8N%96%DC%25%60C%AA%D2%12%8D%96%CBm%05%A2%03R%F7%AF%CE%23y[mCa%AB%FD%60%1A%14%60U%8A%22%FF%AB%90%20%03%C5%AC%D4%C1%20%E7MA%20%C7%8D%F9%C4w%DF%9F%D1m%DA5%85G%BB%F9f.%B3%97HOL%9F%BD%B2&u]%5C%CA%E3oe%CC%CD%F7cF%BA%0AS%9A%AC%BD%84%8CDut%E0mW,%B9%9F%F1%F8-%A1y%F01%AB!%8E%AC%E6%96U%D0%1E%15%05f%18%87%E8(%91%AD%1F%B2%A5%9C%9E%1E_%8E%03P%D4%9D%1F%E0%2535%1D%CEGG%E7%8F%9Ff%01'/%8F%07[%9F%9E'%C2;%A7%EDYi%EF%E7;%8A%02%E3%EF%E4y%8C%8D%AD%B4%B2%E7PY%EA%8E4%09%CAVT%85(D%F1%20%E9%05%0D%D8%E5KJ%BD%FF%81