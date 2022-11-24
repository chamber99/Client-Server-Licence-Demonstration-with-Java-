import javax.crypto.Cipher;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class LicenseManager {

    PrivateKey privateKey;

    PublicKey publicKey;

    Cipher cipher;

    KeyFactory keyFactory;

    FileInputStream fis;
    FileOutputStream fos;


    public LicenseManager() throws IOException {
       /* File privateFile = new File("keys\\private.key"); //TODO burası dosyalar srcdeymiş gibi ayarlanacak
        fis = new FileInputStream(privateFile);

        byte[] priv = fis.readAllBytes();

        for(byte b : priv){
            System.out.print(b + " ");
        }*/


    }


    public String processEncodedInfo(String string) {
        byte[] decoded = Base64.getDecoder().decode(string);


        return "";
    }


    public void processTuple(String string) {
        System.out.println(string);
    }
}
