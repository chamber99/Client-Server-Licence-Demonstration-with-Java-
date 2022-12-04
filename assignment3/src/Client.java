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
    private static PublicKey publicKey; // PublicKey of Client - created from public.key
    private static boolean licenceRecreated;
    private static KeyFactory keyFactory; // To create key
    private static MessageDigest messageDigest;
    private static String md5PlainText; // To print MD5 sum as a HEX string.
    private static final String username = "bkisa_yedmrl"; // Statically declared username
    private static final String serial = "brky-yedm-b465"; // Statically declared serial
    private static String macAdress; // Mac Adress
    private static LicenseManager manager; // Instance of LicenseManager.
    private static String diskSerial; // Disk Serial
    private static String motherboardSerial; // Motherboard Serial
    private static String clientTuple; // The tuple created from system mac address and hardware serials.
    private static File license; // The license.txt file.
    private static FileInputStream inputStream; // FileInputStream for reading key files and license.txt

    public static void main(String[] args) { // Constructor of Client. The whole process starts here with the initialization.
        getPublicKey();
        licenceRecreated = false;
        System.out.println("Client started...");
        getDeviceInformation(); // Our method to get device related information.
        System.out.println("My MAC: " + macAdress);
        System.out.println("My Disk ID: " + diskSerial);
        System.out.println("My Motherboard ID: " + motherboardSerial);

        try {
            messageDigest = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        manager = new LicenseManager(); // Creating the LicenseManager instance
        System.out.println("LicenseManager service started...");

        clientTuple = getTuple(); // The tuple is created after collecting system information

        boolean check = checkLicenseExistence(); // Checking if licence exists.
        System.out.println(check ? "Client -- License file is found" : "Client -- License file is not found");

        if (check) {
            System.out.println("Client -- Verifying the license file found on this device...");
            verifyLicense();
        } else {
            createLicense();
        }

    }

    private static void getPublicKey() {
        File publicKeyFile = new File("keys\\public.key");
        try {
            inputStream = new FileInputStream(publicKeyFile);
            byte[] keyBytes = inputStream.readAllBytes();

            keyFactory = KeyFactory.getInstance("RSA");
            EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(keyBytes);
            publicKey = keyFactory.generatePublic(publicKeySpec);

            inputStream.close();
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }


    }

    private static Consumer<byte[]> licenseManagerConsumer = (encrypted -> { // Consumer for the LicenseManager operation.
        manager.processEncodedInfo(encrypted);
    });

    public static boolean verifyHashfromServer(byte[] signature) {

        md5PlainText = String.format("%032X", new BigInteger(1, signature));

        boolean result = verifyHash(publicKey, signature);
        if (result) {
            File lic = new File("license.txt");
            if (!lic.exists()) {
                System.out.println("Client -- License is not found");
            }
            System.out.println("Client -- Succeed. The license file content is secured and signed by the server.");
        }
        return result;
    }

    private static boolean checkLicenseExistence() { // This method checks if the client has a valid license.
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

    public static void writeNewLicense(byte[] signature) {
        boolean creation;

        license = new File("license.txt");
        try {
            creation = license.createNewFile();
            if (creation || licenceRecreated) {
                FileOutputStream outputStream = new FileOutputStream(license);
                byte[] hashed = hashWithMD5(getTuple());
                md5PlainText = String.format("%032X", new BigInteger(1, hashed));
                outputStream.write(md5PlainText.getBytes(StandardCharsets.UTF_8));
                String divisor = "#####sign#####";
                outputStream.write(divisor.getBytes(StandardCharsets.UTF_8));
                outputStream.write(signature);
                outputStream.close();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void verifyLicense() {
        clientTuple = getTuple();
        byte[] md5Hash = hashWithMD5(clientTuple);

        try {
            byte[] license = inputStream.readAllBytes();
            byte[] signBytes = new byte[128];
            System.arraycopy(license, 46, signBytes, 0, 128);

            inputStream.close();

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
            e.printStackTrace();
        }
    }

    private static void printEncrypted(byte[] encrypted) {
        String encryptedHex = String.format("%032X", new BigInteger(1, encrypted));
        System.out.println("Client -- Encrypted License Text: " + encryptedHex);
    }

    public static void printHashed(byte[] hashed) {
        System.out.print("Client -- MD5 License Text: ");
        md5PlainText = String.format("%032X%n", new BigInteger(1, hashed));
        System.out.print(md5PlainText);
    }

    private static void createLicense() {
        System.out.println("Client -- Raw License Text: " + clientTuple);
        licenseManagerConsumer.accept(encryptWithRSA(clientTuple));
    }

    private static String getTuple() {
        return username + "$" + serial + "$" + macAdress + "$" + diskSerial + "$" + motherboardSerial;
    }

    private static void getDeviceInformation() {
        macAdress = getMacAdress();
        diskSerial = getDiskSerial('C');
        motherboardSerial = getMotherboardSerial();

        CharSequence seq = "nullSerialNumber";
        motherboardSerial = motherboardSerial.replace(seq, "");
        motherboardSerial = motherboardSerial.strip();

        clientTuple = getTuple();
    }

    private static String getMotherboardSerial() {
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
                motherboardSerial = result;
                return result;
            }
            input.close();
        } catch (IOException ex) {
            ex.printStackTrace();
        }
        return "null";
    }

    private static String getDiskSerial(Character letter) {
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

    private static String getMacAdress() {
        InetAddress localHost;
        NetworkInterface networkInterface;

        try {
            localHost = InetAddress.getLocalHost();
            networkInterface = NetworkInterface.getByInetAddress(localHost);
            byte[] hardwareAddress = networkInterface.getHardwareAddress();
            if (hardwareAddress == null) {
                System.err.println("Client -- Connection cannot be established. " +
                        "Please ensure that you have a proper Internet connection.");
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

    private static byte[] encryptWithRSA(String tuple) {
        byte[] keyBytes;

        File publicKeyFile = new File("keys\\public.key");
        if (publicKeyFile.exists() && publicKeyFile.isFile()) {
            try {
                inputStream = new FileInputStream(publicKeyFile);
                keyBytes = inputStream.readAllBytes();

                keyFactory = KeyFactory.getInstance("RSA");
                EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(keyBytes);
                publicKey = keyFactory.generatePublic(publicKeySpec);

                inputStream.close();

                // Cipher for RSA Encryption.
                Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                cipher.init(Cipher.ENCRYPT_MODE, publicKey);

                byte[] tupleBytes = tuple.getBytes(StandardCharsets.UTF_8);

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

    private static byte[] hashWithMD5(String result) {
        byte[] hash;
        hash = messageDigest.digest(result.getBytes(StandardCharsets.UTF_8));
        return hash;
    }

    private static boolean verifyHash(PublicKey publicKey, byte[] input) {
        try {
            // For signing
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(publicKey);
            signature.update(hashWithMD5(clientTuple));
            return signature.verify(input);

        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
        }

        return false;
    }

}
