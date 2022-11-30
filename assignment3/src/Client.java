import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.function.Consumer;

public class Client {


    private PublicKey publicKey; // PublicKey of Client - created from public.key

    private boolean licenceRecreated;
    Signature signature; // For signing
    private KeyFactory keyFactory; // To create key
    private MessageDigest messageDigest;
    private Cipher cipher; // Cipher for RSA Encryption.
    private String md5PlainText; // To print MD5 sum as a HEX string.
    private final String username = "bkisa_yedmrl"; // Statically declared username
    private final String serial = "brky-yedm-b465"; // Statically declared serial
    private String macAdress; // Mac Adress
    private LicenseManager manager; // Instance of LicenseManager.
    private String diskSerial; // Disk Serial
    private String motherboardSerial; // Motherboard Serial
    private String clientTuple; // The tuple created from system mac address and hardware serials.
    private File license; // The license.txt file.
    private FileInputStream inputStream; // FileInputStream for reading key files and license.txt
    private FileOutputStream outputStream;

    public Client() { // Constructor of Client. The whole process starts here with the initialization.
        licenceRecreated = false;
        System.out.println("Client started...");
        getDeviceInformation(); // Our method to get device related information.
        System.out.println("My MAC: " + macAdress);
        System.out.println("My Disk ID: " + diskSerial);
        System.out.println("My Motherboard ID: " + motherboardSerial);

        try {
            this.messageDigest = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        this.manager = new LicenseManager(this); // Creating the LicenseManager instance
        System.out.println("LicenseManager service started...");
        manager.createKeys(); // License manager creating keys
        clientTuple = getTuple(); // The tuple is created after collecting system information

        boolean check = checkLicenseExistence(); // Checking if licence exists.
        System.out.println(check ? "Client -- License file is found" : "Client -- License file is not found");

        if (check) {
            verifyLicense();
        } else {
            //System.out.println("Client -- License file is not found");
            createLicense();
        }

        //System.out.println("Client -- Succeed. The license file content is secured and found by the server.");

        // writeNewLicense();
    }

    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    public Consumer<byte[]> licenseManagerConsumer = (encrypted -> { // Consumer for the LicenseManager operation.
        manager.processEncodedInfo(encrypted);
    });

    public boolean verifyHashfromServer(byte[] signature) {

        this.md5PlainText = String.format("%032X", new BigInteger(1, signature));


        boolean result = verifyHash(publicKey, signature);
        if (result) {
            File lic = new File("license.txt");
            if (!lic.exists()) {
                System.out.println("Client -- License is not found");
            }

            //System.out.println("Client -- License is verified.");
            System.out.println("Client -- Succeed. The license file content is secured and signed by the server.");

        } else {
            System.err.println("Client -- License is corrupted!");
            //createLicense();
        }

        return result;
    }


    private boolean checkLicenseExistence() { // This method checks if the client has a valid license.
        license = new File("license.txt");
        if (license.exists() && license.isFile()) {
            try {
                inputStream = new FileInputStream(license);
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            }
            return true;
        } else {

            return false;
        }
    }

    public void writeNewLicense(byte[] signature) {
        boolean creation;

        license = new File("license.txt");
        try {
            creation = license.createNewFile();

            /*FileWriter writer = new FileWriter(license);
            writer.write(content);
            writer.close();*/
            if (creation || licenceRecreated) {
                outputStream = new FileOutputStream(license);
                byte[] hashed = hashWithMD5(getTuple());
                this.md5PlainText = String.format("%032X", new BigInteger(1, hashed));
                outputStream.write(this.md5PlainText.getBytes(StandardCharsets.UTF_8));
                String divisor = "#####sign#####";
                outputStream.write(divisor.getBytes(StandardCharsets.UTF_8));
                outputStream.write(signature);
                outputStream.close();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void verifyLicense() {
        this.clientTuple = getTuple();
        byte[] md5Hash = hashWithMD5(this.clientTuple);


        //System.out.println("haha" + this.clientTuple);
        try {
            byte[] license = inputStream.readAllBytes();
            //String licenseText = new String(license, StandardCharsets.UTF_8);
            //String[] split = licenseText.split("#####sign#####");


            byte[] signBytes = new byte[128];
            System.arraycopy(license, 46, signBytes, 0, 128);

            String[] split = new String(license, StandardCharsets.UTF_8).split("#####sign#####");
            boolean hashCorrect = String.format("%032X", new BigInteger(1, md5Hash)).equals(split[0]);
            boolean verify = verifyHash(publicKey, signBytes);

            if (hashCorrect && verify) {
                System.out.println("Client -- Succeed. The license is correct.");
            } else {
                licenceRecreated = true;
                System.err.println("Client -- The license file has been broken!");
                System.out.println("Client -- Attempting to create new license for the user.");
                createLicense();
            }


        } catch (IOException e) {
            throw new RuntimeException(e);
        }


    }

    private void printEncrypted(byte[] encrypted) {
        //System.out.println("Client -- Encrypted License Text: " + new String(encrypted, StandardCharsets.UTF_8));

        String encryptedHex = String.format("%032X", new BigInteger(1, encrypted));
        //System.out.println("Client -- Encrypted License Text: " + new String(encrypted);
        System.out.println("Client -- Encrypted License Text: " + encryptedHex);
    }

    public void printHashed(byte[] hashed) {
        System.out.print("Client -- MD5 License Text: ");
        this.md5PlainText = String.format("%032X%n", new BigInteger(1, hashed));
        System.out.print(this.md5PlainText);
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
        InetAddress localHost;
        NetworkInterface networkInterface;

        try {
            localHost = InetAddress.getLocalHost();
            networkInterface = NetworkInterface.getByInetAddress(localHost);
            byte[] hardwareAddress = networkInterface.getHardwareAddress();
            if (hardwareAddress == null) {
                System.err.println("Client -- Connection cannot be established. Please ensure that you have a proper Internet connection.");
                System.err.println("Terminating process..");
                System.exit(-1);
            }

            String[] hexadecimal = new String[hardwareAddress.length];
            for (int i = 0; i < hardwareAddress.length; i++) {
                hexadecimal[i] = String.format("%02X", hardwareAddress[i]);
            }
            return String.join("-", hexadecimal);

        } catch (SocketException | UnknownHostException e) {
            e.printStackTrace();
        }
        return "Mac address cannot be gathered!";
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

                cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
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


    public byte[] hashWithMD5(String result) {
        byte[] hash;
        hash = messageDigest.digest(result.getBytes(StandardCharsets.UTF_8));
        return hash;
    }

    public boolean verifyHash(PublicKey publicKey, byte[] input) {
        try {
            signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(publicKey);
            signature.update(hashWithMD5(this.clientTuple));
            return signature.verify(input);

        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
        }

        return false;
    }

}
