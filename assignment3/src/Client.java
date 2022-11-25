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
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.function.Consumer;

public class Client {
    //TODO mac address falan bulmayı öğren DONE IT LMAO KEKW
    //TODO RSA öğren amk
    //TODO cidden yane

    private PublicKey publicKey;
    Signature signature;
    private KeyFactory keyFactory;
    private Cipher cipher;
    private final String username = "bkisa_yedmrl";
    private final String serial = "brky-yedl-b465";
    private String macAdress;
    private LicenseManager manager;
    private String diskSerial;
    private String motherboardSerial;
    private String clientTuple;
    private File license;
    private FileInputStream inputStream;

    public Client() throws IOException {
        System.out.println("Client started...");
        getDeviceInformation();
        System.out.println("My MAC: " + macAdress);
        System.out.println("My Disk ID: " + diskSerial);
        System.out.println("My Motherboard ID: " + motherboardSerial);

        this.manager = new LicenseManager(this);
        System.out.println("LicenseManager service started...");
        manager.createKeys();
        clientTuple = getTuple();
        boolean check = checkLicenseExistence();
        System.out.println(check ? "Client -- License file is found" : "Client -- License file is not found");

        //System.out.println("Client -- Succeed. The license file content is secured and found by the server.");


    }

    public Consumer<byte[]> licenseManagerConsumer = (encrypted -> {
        //getDeviceInformation();
        //System.out.println(clientTuple + "\n");
        System.out.println(manager.processEncodedInfo(encrypted));
    });

    private boolean checkLicenseExistence() {
        license = new File("license.txt");
        if (license.exists() && license.isFile()) {
            try {
                inputStream = new FileInputStream(license);
            } catch (FileNotFoundException e) {
                System.out.println("License is not found");
            }
            verifyLicense();

            return true;
        } else {
            System.out.println("Client -- License file is not found");
            createLicense();
            return false;
        }
    }

    private void verifyLicense() {

    }

    private void printEncrypted(byte[] encrypted) {
        System.out.print("Client -- Encrypted License Text: ");
        System.out.println(new String(encrypted, StandardCharsets.UTF_8));
    }

    public void printHashed(byte[] hashed) {
        System.out.print("Client -- MD5 License Text: ");
        System.out.println(new String(hashed, StandardCharsets.UTF_8));
    }

    private void createLicense() {
        System.out.println("Client -- Raw License Text: " + clientTuple);
        licenseManagerConsumer.accept(encryptWithRSA(clientTuple));
    }

    private String getTuple() {
        return username + "$" + serial + "$" + macAdress + "$" + diskSerial + "$" + motherboardSerial;
    }

    private void getDeviceInformation() {
        this.macAdress = getMacAdress();
        this.diskSerial = getdiskSerial('C');
        this.motherboardSerial = getMotherboardSerial();

        CharSequence seq = "nullSerialNumber";
        motherboardSerial = motherboardSerial.replace(seq, "");
        motherboardSerial = motherboardSerial.strip();

        this.clientTuple = getTuple();

        //System.out.println("mac: " + macAdress);
        //System.out.println("disk: " + diskSerial);
        //System.out.println("mobo: " + motherboardSerial);

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
                CharSequence seq = "nullSerialNumber";
                this.motherboardSerial = result;
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

    private byte[] encryptWithRSA(String tuple) {
        byte[] keyBytes;

        File publicKeyFile = new File("keys\\public.key");
        if (publicKeyFile.exists() && publicKeyFile.isFile()) {
            try {
                inputStream = new FileInputStream(publicKeyFile);
                keyBytes = inputStream.readAllBytes();

                keyFactory = KeyFactory.getInstance("RSA");
                EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(keyBytes);
                this.publicKey = keyFactory.generatePublic(publicKeySpec);

                cipher = Cipher.getInstance("RSA/ECB/NoPadding");
                cipher.init(Cipher.ENCRYPT_MODE, this.publicKey);

                byte[] tupleBytes = tuple.getBytes(StandardCharsets.UTF_8);

                //tupleBytes = padPlainText(tupleBytes);

                byte[] encryptedBytes = cipher.doFinal(tupleBytes);

                printEncrypted(encryptedBytes);

                return encryptedBytes;

            } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException |
                     InvalidKeyException | BadPaddingException | IllegalBlockSizeException ex) {
                ex.printStackTrace();
            }
        }
        return null;
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

    public boolean verifyHash(PublicKey publicKey, byte[] input) {
        try {
            signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(publicKey);

            boolean verify = signature.verify(input);
            return verify;

        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
        }

        return false;
    }


}
