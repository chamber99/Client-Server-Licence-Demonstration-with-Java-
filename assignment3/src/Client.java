import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.function.Consumer;

public class Client {
    //TODO mac address falan bulmayı öğren DONE IT LMAO KEKW
    //TODO RSA öğren amk
    //TODO cidden yane

    private PrivateKey privateKey;

    private KeyFactory keyFactory;

    private Cipher cipher;


    private final String username = "bkisa_yedmrl";
    private final String serial = "brky-yedl-b465";


    private String macAdress;
    private String diskSerial;
    private String motherboardSerial;
    private String clientTuple;
    private File license;
    private FileInputStream inputStream;
    private FileOutputStream outputStream;

    public Client() throws IOException {
        System.out.println(checkLicenseExistence());

        //getDeviceInformation(); //for testing
        System.out.println(" ++++++++ ");
        //System.out.println(getTuple());
        //licenseManager.accept(getTuple());

        clientTuple = getTuple();

        System.out.println(clientTuple + "\n" + encryptWithRSA(clientTuple));

        licenseManager.accept(encryptWithRSA(clientTuple));

    }

    public Consumer<String> licenseManager = (string -> {
        LicenseManager manager;
        manager = new LicenseManager();
        System.out.println(manager.processEncodedInfo(string));
    });

    private boolean checkLicenseExistence() {
        license = new File("license.txt");
        if (license.exists() && license.isFile()) {
            try {
                inputStream = new FileInputStream(license);
            } catch (FileNotFoundException e) {
                e.printStackTrace();
                throw new RuntimeException(e);
            }
            verifyLicense();

            return true;
        } else {
            createLicense();
            return false;
        }
    }

    private void verifyLicense() {

    }

    private void createLicense() {
        getDeviceInformation();

    }

    private String getTuple() {
        CharSequence seq = "nullSerialNumber";
        motherboardSerial = motherboardSerial.replace(seq, "");
        motherboardSerial = motherboardSerial.strip();
        return username + "$" + serial + "$" + macAdress + "$" + diskSerial + "$" + motherboardSerial;
    }

    private void getDeviceInformation() {
        this.macAdress = getMacAdress();
        this.diskSerial = getdiskSerial('C');
        this.motherboardSerial = getMotherboardSerial();

        System.out.println("mac: " + macAdress);
        System.out.println("disk: " + diskSerial);
        System.out.println("mobo: " + motherboardSerial);

    }

    private String getMotherboardSerial() {
        try {
            String result = null;
            Process p = Runtime.getRuntime().exec("wmic baseboard get serialnumber");
            BufferedReader input = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line;
            while ((line = input.readLine()) != null) {
                result += line;
            }

            assert result != null;
            if (result.equalsIgnoreCase(" ")) {
                System.out.println("Result is empty");
            } else {
                return result;
            }
            input.close();
        } catch (IOException ex) {
            ex.printStackTrace();
        }
        return "null";
    }

    public String getdiskSerial(Character letter) {
        String line;
        String serial = null;
        Process process;
        try {
            process = Runtime.getRuntime().exec("cmd /c vol " + letter + ":");
            BufferedReader in = new BufferedReader(new InputStreamReader(process.getInputStream()));
            while ((line = in.readLine()) != null) {
                if (line.toLowerCase().contains("serial number")) {
                    String[] strings = line.split(" ");
                    serial = strings[strings.length - 1];
                }
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return serial;
    }

    private String getMacAdress() {
        InetAddress localHost = null;
        NetworkInterface networkInterface = null;

        try {
            localHost = InetAddress.getLocalHost();
            networkInterface = NetworkInterface.getByInetAddress(localHost);
            byte[] hardwareAddress = networkInterface.getHardwareAddress();

            String[] hexadecimal = new String[hardwareAddress.length];
            for (int i = 0; i < hardwareAddress.length; i++) {
                hexadecimal[i] = String.format("%02X", hardwareAddress[i]);
            }
            return String.join("-", hexadecimal);

        } catch (SocketException | UnknownHostException e) {
            throw new RuntimeException(e);
        }
    }

    private String encryptWithRSA(String tuple) {
        byte[] keyBytes;

        File privateKeyFile = new File("keys\\private.key");
        if (privateKeyFile.exists() && privateKeyFile.isFile()) {
            try {
                inputStream = new FileInputStream(privateKeyFile);
                keyBytes = inputStream.readAllBytes();

                keyFactory = KeyFactory.getInstance("RSA");
                EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(keyBytes);
                privateKey = keyFactory.generatePrivate(privateKeySpec);

                cipher = Cipher.getInstance("RSA/ECB/NoPadding");
                cipher.init(Cipher.ENCRYPT_MODE, privateKey);

                byte[] tupleBytes = tuple.getBytes(StandardCharsets.UTF_8);

                tupleBytes = padPlainText(tupleBytes);

                byte[] encryptedBytes = cipher.doFinal(tupleBytes);

                return Base64.getEncoder().encodeToString(encryptedBytes);

            } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException |
                     InvalidKeyException | BadPaddingException | IllegalBlockSizeException ex) {
                ex.printStackTrace();
            }
        }
        return "Something went wrong.";
    }

    public byte[] padPlainText(byte[] plainText) {
        for (byte b : plainText) {
            System.out.println(b);
        }
        byte[] byteArray = plainText;
        int remainder = byteArray.length % 8;
        byte[] padded = new byte[byteArray.length + (8 - remainder)];
        Arrays.fill(padded, (byte) (8 - remainder));
        int index = 0;
        for (byte b : byteArray) {
            padded[index++] = b;
        }
        return padded;
    }


}