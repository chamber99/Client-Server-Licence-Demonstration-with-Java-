import java.io.IOException;
import java.util.Properties;

public class Client {

    private final String username = "bkisa_yedmrl";
    private final String serial = "brky-yedl-b465";
    private String macAdress;
    private String diskSerial;
    private String motherboardSerial;

    public Client() throws IOException {
        getDeviceInformation();
    }

    private void getDeviceInformation() throws IOException {
        Properties systemProperties = System.getProperties();
        String info = systemProperties.getProperty("user.name");
        System.out.println(info);

    }




}
