import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class LicenseManager {

    PrivateKey privateKey;

    Client client;

    Signature privateSignature;
    MessageDigest messageDigest;

    PublicKey publicKey;

    Cipher cipher;

    String acquiredTuple;

    KeyFactory keyFactory;

    FileInputStream fis;
    FileOutputStream fos;


    public LicenseManager(Client clientVar) {
        this.client = clientVar;
        try {
            messageDigest = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }


    }

    public void createKeys() {
        File privateKeyFile = new File("keys\\private.key"); //TODO burası dosyalar srcdeymiş gibi ayarlanacak
        File publicKeyFile = new File("keys\\public.key"); //TODO burası dosyalar srcdeymiş gibi ayarlanacak
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

            } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
                e.printStackTrace();
            }
        }
    }

    public byte[] clearPadding(byte[] padded) {
        byte lastByte = padded[padded.length - 1];
        int plainTextLength = padded.length - lastByte;
        byte[] withoutPadding = new byte[plainTextLength];
        for (int i = 0; i < plainTextLength; i++) {
            withoutPadding[i] = padded[i];
        }
        return withoutPadding;
    }

    public String processEncodedInfo(byte[] encrypted) {
        try {
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

            cipher.init(Cipher.DECRYPT_MODE, privateKey);

            byte[] decrypted = cipher.doFinal(encrypted);

            //decrypted = clearPadding(decrypted);

            String result = new String(decrypted, StandardCharsets.UTF_8);

            byte[] hashed = hashWithMD5(result);

            String md5PlainText = String.format("%032X", new BigInteger(1, hashed));

            client.printHashed(hashed);

            System.out.println("Server is being requested...");
            System.out.println("Server -- Incoming Encrypted Text: " + new String(encrypted, StandardCharsets.UTF_8));
            System.out.println("Server -- Decrypted Text: " + result);
            System.out.println("Server -- MD5 Plain License Text: " + md5PlainText);


            sign(hashed);


            return result;

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException |
                 BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    public byte[] hashWithMD5(String result) {
        byte[] hash;
        hash = messageDigest.digest(result.getBytes(StandardCharsets.UTF_8));
        return hash;
    }


    public byte[] sign(byte[] hash) {
        try {
            privateSignature = Signature.getInstance("SHA256withRSA");
            privateSignature.initSign(privateKey);
            privateSignature.update(hash);

            byte[] sign = privateSignature.sign();

            System.out.println("Server -- Digital Signature: " + new String(sign, StandardCharsets.UTF_8));

            boolean verify = client.verifyHashfromServer(sign);
            //System.out.println(client.verifyHash(publicKey, sign));

            if (verify) {
                client.writeNewLicense();
            }

            return sign;

        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new RuntimeException(e);
        }


    }


    public void processTuple(String string) {
        System.out.println(string);
    }
}
