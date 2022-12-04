import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class LicenseManager {
    PrivateKey privateKey; // Private key of LicenseManager
    Signature privateSignature; // The Signature object for signing data
    MessageDigest messageDigest; // MessageDigest for MD5 Hashing
    PublicKey publicKey; // Public key of LicenseManager
    Cipher cipher; // Cipher for decryption
    KeyFactory keyFactory; // KeyFactory for generation of keys from .key files.
    FileInputStream fis; // File Input Stream for reading .key files.

    public LicenseManager() {
        createKeys(); // License manager creating keys as soon as it gets instantiated.
        try {
            messageDigest = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private void createKeys() {
        File privateKeyFile = new File("keys\\private.key");
        File publicKeyFile = new File("keys\\public.key");
        if (privateKeyFile.exists() && publicKeyFile.exists() && privateKeyFile.isFile() && publicKeyFile.isFile()) {
            try {
                fis = new FileInputStream(privateKeyFile);
                byte[] priv = fis.readAllBytes();
                fis = new FileInputStream(publicKeyFile);
                byte[] pub = fis.readAllBytes();

                keyFactory = KeyFactory.getInstance("RSA");

                EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(priv);
                EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(pub);

                publicKey = keyFactory.generatePublic(publicKeySpec);
                privateKey = keyFactory.generatePrivate(privateKeySpec);

                fis.close();

            } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
                e.printStackTrace();
            }
        }
    }

    public void processEncodedInfo(byte[] encrypted) {
        try {
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

            cipher.init(Cipher.DECRYPT_MODE, privateKey);

            byte[] decrypted = cipher.doFinal(encrypted);

            //decrypted = clearPadding(decrypted);

            String result = new String(decrypted, StandardCharsets.UTF_8);

            byte[] hashed = hashWithMD5(result);

            String md5PlainText = String.format("%032X", new BigInteger(1, hashed));

            Client.printHashed(hashed);

            System.out.println("Server is being requested...");

            String encryptedHex = String.format("%032X", new BigInteger(1, encrypted));

            //System.out.println("Server -- Incoming Encrypted Text: " + new String(encrypted, StandardCharsets.UTF_8));
            System.out.println("Server -- Incoming Encrypted Text: " + encryptedHex);
            System.out.println("Server -- Decrypted Text: " + result);
            System.out.println("Server -- MD5 Plain License Text: " + md5PlainText);


            sign(hashed);


        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException |
                 BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    private byte[] hashWithMD5(String result) {
        byte[] hash;
        hash = messageDigest.digest(result.getBytes(StandardCharsets.UTF_8));
        return hash;
    }

    private void sign(byte[] hash) {
        try {
            privateSignature = Signature.getInstance("SHA256withRSA");
            privateSignature.initSign(privateKey);
            privateSignature.update(hash);

            byte[] sign = privateSignature.sign();

            System.out.print("Server -- Digital Signature: ");
            String signPlainText = String.format("%032X", new BigInteger(1, sign));
            System.out.println(signPlainText);

            boolean verify = Client.verifyHashfromServer(sign);


            if (verify) {
                Client.writeNewLicense(sign);
            }

        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new RuntimeException(e);
        }


    }
}