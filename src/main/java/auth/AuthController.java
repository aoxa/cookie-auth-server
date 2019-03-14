package auth;

import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

@RestController
public class AuthController {

    @RequestMapping("/")
    public String index(HttpServletRequest req, HttpServletResponse res) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        SecureRandom secureRandom = new SecureRandom();

        byte[] iv = new byte[16];

        secureRandom.nextBytes(iv);

        IvParameterSpec ivspec = new IvParameterSpec(iv);

        SecretKeySpec keySpec = new SecretKeySpec("abcdefghijklmnopponmlkjihgfedcba".getBytes(), "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivspec);

        Cookie myCookie =
                new Cookie("AUTH_ID", Base64.getEncoder().encodeToString(iv) + Base64.getEncoder().encodeToString(cipher.doFinal("hello!".getBytes())));

        res.addCookie(myCookie);

        return "<a href=\"http://localhost:8080/users/login.html\">here</a>";
    }
}