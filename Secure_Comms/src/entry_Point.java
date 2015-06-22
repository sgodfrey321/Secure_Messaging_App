import javax.crypto.*;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;

/**
 * Created by samgodfrey on 4/16/15.
 */
public class entry_Point {
    static boolean report;
    public static void main(String[] args) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, InterruptedException, IOException, IllegalBlockSizeException, BadPaddingException{
        Alice_Main nA;
        if(args.length > 0){
            String arg = args[0];
            if(arg.equals("-v")){
                report = true;
                nA = new Alice_Main(report);
            }
            else{
                System.out.println("Invalid Argument. Not Reporting");
                nA = new Alice_Main();
            }
        }
        else{
            nA = new Alice_Main();
        }
        importAliceInfo(nA);
        importCAInfo(nA);
        System.out.println("System paramaters set. Choose an option below:\r");
        System.out.println("1) Connect to another host");

        BufferedReader br = new BufferedReader(new InputStreamReader(
                System.in));
        int x = 0;
            String s = br.readLine();
            x = Integer.parseInt(s);
        if(x == 1){
            System.out.println("Please Enter The IP address of the desired host:\r");
            s = br.readLine();
            nA.connectToHost(s, 0);
        }
        if(x == 2){
            System.out.println("Please Enter The Ip address of the desired host (SSL):\r");
            s = br.readLine();
            nA.connectToHost(s, 1);
        }
       }
    public static void importAliceInfo(Alice_Main alice){
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
        modulus = modulus.replace(":","");

        String p1 = "00:f8:9a:d0:88:f3:0b:ba:4f:2c:35:a4:e0:4a:c8:\n" +
                "55:ab:c9:86:5e:a1:ee:ff:7c:8c:60:be:73:a2:6d:\n" +
                "e5:9f:f9:b7:65:33:60:ec:43:8e:ce:73:b5:da:ab:\n" +
                "9b:97:4e:a2:58:16:76:cc:55:a3:c2:33:73:fd:79:\n" +
                "68:98:55:cf:07";
        p1 = p1.replace("\n", "");
        p1 = p1.replace(":","");


        String p2 = "00:ca:14:89:c3:99:60:02:60:a0:06:bb:4e:fa:51:\n" +
                "5d:48:6a:51:60:55:7a:3e:58:20:d3:80:27:e3:42:\n" +
                "36:95:c0:63:3d:45:c1:78:df:18:f6:93:c4:d6:60:\n" +
                "67:db:f1:9e:fd:cd:32:92:2e:22:ce:4c:51:c6:63:\n" +
                "9e:5c:79:97:3d";
        p2 = p2.replace("\n", "");
        p2 = p2.replace(":","");

        alice.setPrimes(p1, p2);

        String privateKey = "3e:26:bd:0f:dc:c9:cb:4c:cf:ad:ec:24:42:46:d7:\n" +
                "32:6b:fc:a2:d4:3f:a5:c7:72:b6:a7:24:55:37:e9:\n" +
                "5c:7c:b1:90:99:0f:26:ba:4a:da:31:1f:d6:a3:4c:\n" +
                "66:46:89:7d:4a:3c:eb:c9:99:cf:3d:86:39:56:65:\n" +
                "71:96:52:0d:13:cf:cc:b9:0e:bf:6d:9a:59:4e:9d:\n" +
                "ac:31:0d:3d:11:4a:a1:9b:7d:9d:97:90:46:bd:e5:\n" +
                "6c:2e:64:5b:00:c9:77:4c:0b:64:71:58:1d:5c:99:\n" +
                "25:1f:80:ab:1d:5b:48:67:08:7c:ad:e8:1e:ff:b7:\n" +
                "ef:fe:d0:ee:24:ec:1c:21";
        privateKey = privateKey.replace("\n", "");
        privateKey = privateKey.replace(":","");


        alice.importPrivateRSAKey(modulus,privateKey);
    }
    public static void importCAInfo(Alice_Main alice){
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

        String pubKey = "10001";

        alice.importCAPublicKey(modulus, pubKey);
    }
    public static void importBobInfo(Alice_Main alice) {
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

        alice.importPublicRSAKey(modulus, "65537");
    }
}
