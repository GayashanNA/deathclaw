import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.FileUtils;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

/**
 * Created by Sandamal on 9/18/2015.
 */
public class FalloutShelter {

    private static final String salt = "tu89geji340t89u2";
    private static final String passPhrase = "UGxheWVy";
    public static final String charsetName = "UTF-8";

    public static void main(String[] args) throws IOException {
        if (args.length < 1) {
            System.out.println("Usage: FOSDecrypt.exe input_file");
        }

        String path = "Vault1.sav";
        //String data = File.ReadAllText (args [0]);
        byte[] encodedByteArray = Files.readAllBytes(Paths.get(path));
        String data = new String(encodedByteArray);

        if (IsBase64String(data)) {
            try {
                decrypt(encodedByteArray);
            } catch (Exception e) {
                e.printStackTrace();
            }
        } else {
            try {
                encrypt(encodedByteArray);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    public static String decrypt(byte[] encryptedText) throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        byte[] deEncryptedText = Base64.decodeBase64(encryptedText);
        byte[] saltBytes = salt.getBytes(charsetName);
        byte[] passPhraseBytes;

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        PBEKeySpec pbeKeySpec = new PBEKeySpec(passPhrase.toCharArray(), saltBytes, 1000, 384);
        Key secretKey = factory.generateSecret(pbeKeySpec);
        passPhraseBytes = new byte[32];
        System.arraycopy(secretKey.getEncoded(), 0, passPhraseBytes, 0, 32);

        //aesKey is 128, 196 or 256-bit key (8, 12 or 16 byte array)
        SecretKeySpec secretKeySpec = new SecretKeySpec(passPhraseBytes, "AES");
        // initialization vector
        IvParameterSpec ivSpec = new IvParameterSpec(saltBytes);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivSpec);
        byte[] decrypted = cipher.doFinal(deEncryptedText);

        File file = new File("test.txt");
        try {
            FileUtils.writeByteArrayToFile(file, decrypted);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return new String(decrypted);
    }


    public static String encrypt(byte[] plainTextBytes) throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        byte[] saltBytes = salt.getBytes(charsetName);
        byte[] passPhraseBytes;

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        PBEKeySpec pbeKeySpec = new PBEKeySpec(passPhrase.toCharArray(), saltBytes, 1000, 384);
        Key secretKey = factory.generateSecret(pbeKeySpec);
        passPhraseBytes = new byte[32];
        System.arraycopy(secretKey.getEncoded(), 0, passPhraseBytes, 0, 32);

        //aesKey is 128, 196 or 256-bit key (8, 12 or 16 byte array)
        SecretKeySpec secretKeySpec = new SecretKeySpec(passPhraseBytes, "AES");
        // initialization vector
        IvParameterSpec ivSpec = new IvParameterSpec(saltBytes);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivSpec);
        byte[] encrypted = cipher.doFinal(plainTextBytes);
        return Base64.encodeBase64String(encrypted);
    }

    public static boolean IsBase64String(String str) {
        str = str.trim();
        return str.matches("^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)$");
    }
}
