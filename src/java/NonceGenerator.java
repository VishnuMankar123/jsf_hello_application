import java.security.SecureRandom;
import java.util.Base64;

public class NonceGenerator {
    private static final SecureRandom secureRandom = new SecureRandom();
    private static final Base64.Encoder base64Encoder = Base64.getUrlEncoder();

    public static String generateNonce() {
        byte[] nonceBytes =  new byte[16];
        secureRandom.nextBytes(nonceBytes);
        return base64Encoder.encodeToString(nonceBytes);
    }
}