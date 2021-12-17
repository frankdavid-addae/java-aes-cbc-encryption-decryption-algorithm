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

//        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
//        keyGenerator.init(256);
        byte[] key = MessageDigest.getInstance("SHA-256").digest(ENCRYPTION_KEY.getBytes(StandardCharsets.UTF_8));
        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");

        IvParameterSpec ivKey = new IvParameterSpec(ENCRYPTION_IV.getBytes(StandardCharsets.UTF_8));


        //Encrypt data
        Cipher encryptionCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        encryptionCipher.init(Cipher.ENCRYPT_MODE, secretKey, ivKey);
        String data = SRC_STRING_TO_ENCRYPT;
        byte[] encryptedDataBytes = encryptionCipher.doFinal(data.getBytes());
        String encryptedData = Base64.getEncoder().encodeToString(encryptedDataBytes);
        System.out.println("Encrypted Data = " + encryptedData);

        //Decrypt the encrypted data
        Cipher decryptionCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        decryptionCipher.init(Cipher.DECRYPT_MODE, secretKey, ivKey);
        byte[] decryptedDataBytes = decryptionCipher.doFinal(SRC_STRING_TO_DECRYPT.getBytes());
//        byte[] decryptedDataBytes = decryptionCipher.doFinal(encryptedDataBytes);
        String decryptedData = new String(decryptedDataBytes);
        System.out.println("Decrypted Data = " + decryptedData);
    }
}