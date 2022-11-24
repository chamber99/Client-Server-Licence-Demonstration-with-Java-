import java.io.*;
import java.security.PrivateKey;
import java.security.PublicKey;

public class LicenseManager {

    PrivateKey privateKey;
    PublicKey publicKey;

    FileInputStream fis;
    FileOutputStream fos;


    public LicenseManager() throws IOException {
        File privateFile = new File("keys\\private.key"); //TODO burası dosyalar srcdeymiş gibi ayarlanacak
        fis = new FileInputStream(privateFile);

        byte[] priv = fis.readAllBytes();

        for(byte b : priv){
            System.out.print(b + " ");
        }





    }

    public void processTuple(String string) {
        System.out.println(string);
    }
}
