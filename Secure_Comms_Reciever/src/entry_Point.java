import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import java.io.*;
import java.security.SignatureException;

/**
 * Created by samgodfrey on 4/17/15.
 */
public class entry_Point {
    static boolean report = false;
    public static void main(String[] args) throws SignatureException, IOException, IllegalBlockSizeException, BadPaddingException, InterruptedException {
        Bob_Main b;
        if(args.length > 0){
            String arg = args[0];
            if(arg.equals("-v")){
                report = true;
                b = new Bob_Main(report);
            }
            else{
                System.out.println("Invalid Argument. Not Reporting");
                b = new Bob_Main();
            }
        }
        else{
            b = new Bob_Main();
        }
        importPublicKeyForBob(b);
        importPublicKeyForAlice(b);
        importBobInfo(b);
        importCAInfo(b);
        b.startClient();

    }

    public static void importBobInfo(Bob_Main bob) {
        String p1 = "00:ea:7f:49:22:69:a6:74:3b:41:ac:4a:85:b6:82:\n" +
                "c3:85:ef:bf:9f:f4:a8:7a:f8:de:01:ac:ea:a7:f8:\n" +
                "b9:54:5f:53:dd:e4:f5:a9:4c:64:5c:cf:32:34:25:\n" +
                "6a:3d:98:31:92:c4:d4:bc:ab:dd:79:33:6b:29:db:\n" +
                "8a:b7:2c:87:01";
        p1 = p1.replace("\n", "");
        p1 = p1.replace(":","");


        String p2 = "00:e2:ee:50:8a:8a:98:54:b8:a4:3f:0d:ae:c4:30:\n" +
                "88:30:2c:66:ac:a0:45:5e:31:5f:3a:0c:1b:cb:7f:\n" +
                "98:2a:30:bf:46:f4:ae:19:7e:52:91:7e:39:e8:89:\n" +
                "f0:9c:79:36:42:01:f8:0a:0e:25:b1:23:40:9f:6d:\n" +
                "41:27:30:c4:77";
        p2 = p2.replace("\n", "");
        p2 = p2.replace(":","");

        bob.setPrimes(p1, p2);

        String modulus = "00:cf:de:aa:ad:0d:af:7f:88:36:6f:f2:07:ac:0c:\n" +
                "ed:b0:f6:40:53:75:5d:8c:c0:ea:8c:d6:aa:8d:32:\n" +
                "90:13:a2:88:b6:21:45:3c:62:34:c5:83:9a:4c:a9:\n" +
                "8e:2a:59:b8:bf:8d:5a:8a:d9:65:9e:2e:e4:c1:b0:\n" +
                "5b:05:ce:b4:98:a6:17:59:3a:0d:e3:06:eb:0b:d0:\n" +
                "cb:16:38:5e:3f:05:0d:1e:f3:33:94:0a:cc:d5:00:\n" +
                "cf:9a:fd:c9:9b:a6:44:e4:01:7a:9b:90:e3:c7:79:\n" +
                "b7:31:f0:e7:33:c7:aa:e7:9b:9b:12:50:7a:57:07:\n" +
                "ff:b9:de:16:e4:b4:3f:85:77";
        modulus = modulus.replace("\n", "");
        modulus = modulus.replace(":", "");

        String privateKey = "16:9c:99:22:53:ff:c8:36:af:fd:43:6d:b4:38:7f:\n" +
                "ce:a5:2a:e0:29:3f:30:e5:77:5e:34:a7:be:ce:46:\n" +
                "3f:ec:89:44:8e:9f:f2:6e:98:60:f7:ec:db:f4:01:\n" +
                "c3:f7:98:92:35:b5:28:af:77:4f:5a:b8:85:9d:42:\n" +
                "79:82:3f:c0:bc:f6:d2:20:6e:2e:a0:92:f6:eb:5b:\n" +
                "b0:d4:a9:f8:e7:98:6c:e3:eb:14:17:08:21:cc:4d:\n" +
                "a5:80:da:50:df:ba:da:91:75:6d:1f:5d:38:a0:81:\n" +
                "b4:04:5e:c2:d9:2d:be:69:89:83:ba:f5:51:ea:25:\n" +
                "ce:a3:52:bb:fe:e0:2a:01";
        privateKey = privateKey.replace("\n", "");
        privateKey = privateKey.replace(":", "");

        bob.importPrivateRSAKey(modulus, privateKey);
    }

    public static void importCAInfo(Bob_Main bob) {
        String modulus = "00:b8:4e:8d:b2:c7:df:14:36:ab:7a:7f:cf:f7:b0:\n" +
                "2c:e7:6b:99:b4:8a:a2:26:0f:6d:00:ce:3f:56:30:\n" +
                "7a:be:64:1a:49:2d:2f:74:76:28:a6:0b:6c:53:dd:\n" +
                "4d:b5:af:2d:cf:53:f2:dc:78:5e:a6:1c:77:6b:81:\n" +
                "7b:fe:18:e2:75:a8:ac:20:df:95:5f:62:75:b2:c3:\n" +
                "b1:7c:08:17:bd:c0:44:6d:98:10:9b:5d:92:8c:f1:\n" +
                "61:10:c1:21:19:fa:6d:85:57:75:c2:fd:1d:5b:a5:\n" +
                "25:7b:0d:5b:e9:3c:84:17:49:4e:b9:c3:25:32:9e:\n" +
                "77:95:9d:29:76:ac:0a:d5:7f";
        modulus = modulus.replace("\n", "");
        modulus = modulus.replace(":", "");

        String privateKey = "70:a6:8a:d3:60:79:08:48:d6:0c:dc:bc:47:7f:26:\n" +
                "23:18:d0:6c:da:63:7b:71:e8:45:1a:ca:f9:aa:4e:\n" +
                "0b:ba:f1:9a:12:85:33:e0:d8:bd:8c:b3:dc:9a:a2:\n" +
                "59:cf:45:e7:b8:3e:f3:e4:9a:ad:5b:2e:de:c5:d8:\n" +
                "fc:99:47:28:6b:ae:1c:cb:ff:f7:02:a1:bb:73:d8:\n" +
                "3d:e9:f5:01:88:82:43:c2:7a:67:43:69:d9:29:9a:\n" +
                "e9:86:61:02:04:90:e6:79:7c:a8:05:0a:f7:a3:4d:\n" +
                "44:9c:e9:9f:64:f8:0c:10:21:ac:e6:37:ca:43:64:\n" +
                "7e:1b:42:68:f0:e9:76:01";

        privateKey = privateKey.replace("\n", "");
        privateKey = privateKey.replace(":", "");

        bob.importCAPrivateKey(modulus, privateKey);
    }

    public static void importPublicKeyForBob(Bob_Main bob) {


        String modulus = "00:cf:de:aa:ad:0d:af:7f:88:36:6f:f2:07:ac:0c:\n" +
                "ed:b0:f6:40:53:75:5d:8c:c0:ea:8c:d6:aa:8d:32:\n" +
                "90:13:a2:88:b6:21:45:3c:62:34:c5:83:9a:4c:a9:\n" +
                "8e:2a:59:b8:bf:8d:5a:8a:d9:65:9e:2e:e4:c1:b0:\n" +
                "5b:05:ce:b4:98:a6:17:59:3a:0d:e3:06:eb:0b:d0:\n" +
                "cb:16:38:5e:3f:05:0d:1e:f3:33:94:0a:cc:d5:00:\n" +
                "cf:9a:fd:c9:9b:a6:44:e4:01:7a:9b:90:e3:c7:79:\n" +
                "b7:31:f0:e7:33:c7:aa:e7:9b:9b:12:50:7a:57:07:\n" +
                "ff:b9:de:16:e4:b4:3f:85:77";
        modulus = modulus.replace("\n", "");
        modulus = modulus.replace(":", "");


        String publicKey = "65537";


        bob.importPublicRSAKeyForBob(modulus, publicKey);
    }

    public static void importPublicKeyForAlice(Bob_Main bob){

        String modulus = "00:c4:3e:1a:6d:26:f2:23:4e:87:68:c9:1d:ed:4a:\n" +
                "77:03:0c:78:5c:f5:53:27:9a:de:7a:5f:bf:3a:37:\n" +
                "ed:b3:9a:f0:08:06:4f:d2:55:5e:88:36:c9:7b:53:\n" +
                "c2:59:ba:3c:ba:ba:e8:a3:df:82:02:29:9b:8a:25:\n" +
                "61:89:0c:d2:9c:72:f8:60:14:f0:f8:ca:5f:dc:87:\n" +
                "40:fd:79:9c:50:b5:a4:50:32:fe:3b:92:5d:69:a4:\n" +
                "49:63:60:65:ae:41:86:1b:18:e9:21:90:c1:27:36:\n" +
                "09:9f:35:23:a0:c1:6d:6b:26:a3:20:b0:ea:0e:fc:\n" +
                "87:a9:a0:f2:0e:47:de:75:ab";
        modulus = modulus.replace("\n", "");
        modulus = modulus.replace(":", "");

        String privateKey = "65537";

        bob.importPublicRSAKeyForAlice(modulus, privateKey);
    }
}
