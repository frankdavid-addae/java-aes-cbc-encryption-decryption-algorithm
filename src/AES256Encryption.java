import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Base64;

public class AES256Encryption {
    private static final String ENCRYPTION_KEY = "";
    private static final String ENCRYPTION_IV = "";
    private static final String SRC_STRING_TO_ENCRYPT = "";
    private static final String SRC_STRING_TO_DECRYPT = "";

    public static void main(String[] args) throws
            NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException {

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        byte[] key = MessageDigest.getInstance("SHA-256").digest(ENCRYPTION_KEY.getBytes(StandardCharsets.UTF_8));
        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");

        IvParameterSpec ivKey = new IvParameterSpec(ENCRYPTION_IV.getBytes(StandardCharsets.UTF_8));


        //Encrypt Hello world message
        Cipher encryptionCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        encryptionCipher.init(Cipher.ENCRYPT_MODE, secretKey, ivKey);
        String message = SRC_STRING_TO_ENCRYPT;
        byte[] encryptedMessageBytes =
                encryptionCipher.doFinal(message.getBytes());
        String encryptedMessage =
                Base64.getEncoder().encodeToString(encryptedMessageBytes);
        System.out.println("Encrypted message = "+encryptedMessage);

        //Decrypt the encrypted message
        Cipher decryptionCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        decryptionCipher.init(Cipher.DECRYPT_MODE, secretKey, ivKey);
//        byte[] decryptedMessageBytes =
//                decryptionCipher.doFinal(SRC_STRING_TO_DECRYPT.getBytes());
        byte[] decryptedMessageBytes =
                decryptionCipher.doFinal(encryptedMessageBytes);
        String decryptedMessage = new String(decryptedMessageBytes);
        System.out.println("decrypted message ="+decryptedMessage);
    }
}