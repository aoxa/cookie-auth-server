package auth;

import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

@RestController
public class AuthController {

    public static final String LOCATION = "https://ringcentral-stage.cloud.answerhub.com/users/login.html";

    @RequestMapping("/abc/")
    public void index(HttpServletRequest req, HttpServletResponse res) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException {
        SecureRandom secureRandom = new SecureRandom();

        byte[] iv = new byte[16];

        secureRandom.nextBytes(iv);

        // Test static iv
        // iv = "abcdefghijklmnop".getBytes();

        IvParameterSpec ivspec = new IvParameterSpec(iv);

        SecretKeySpec keySpec = new SecretKeySpec("abcdefghijklmnopponmlkjihgfedcba".getBytes(), "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivspec);

        String authValue = getCookieEncryptedValue(iv, cipher);

        res.addCookie(buildAuthCookie(authValue));

        res.sendRedirect(LOCATION);
        // return "<a href=\"\">here</a>";
    }

    private Cookie buildAuthCookie(String authValue) throws UnsupportedEncodingException, MalformedURLException {
        Cookie cookie = new Cookie("ANSWER_HUB_SSO", URLEncoder.encode(authValue, "UTF-8"));

        cookie.setPath("/");

        cookie.setMaxAge(129600); //With it or without, makes no difference.

        URL urlToRedirect = new URL(LOCATION);

        cookie.setDomain(urlToRedirect.getHost());//With it or without, makes no difference.
        return cookie;
    }

    private String getCookieEncryptedValue(byte[] iv, Cipher cipher) throws IllegalBlockSizeException, BadPaddingException {
        return Base64.getEncoder().encodeToString(iv) +
                Base64.getEncoder().encodeToString(
                        cipher.doFinal("{\"userId\":\"276327\",\"userName\":\"Aoxa\",\"email\":\"pedro.zuppelli@gmail.com\"}".getBytes()));
    }
}