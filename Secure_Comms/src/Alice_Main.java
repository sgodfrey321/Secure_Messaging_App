/**
 * Created by samgodfrey on 4/16/15.
 */
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.*;
import javax.xml.crypto.Data;
import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.*;
import java.security.interfaces.*;
import java.security.spec.*;
import java.io.DataOutputStream;
import java.util.Arrays;


public class Alice_Main {
    final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();

    private boolean report, ssl;

    private Cipher rsaEncryption;
    private Cipher rsaDecrytpion;
    private Cipher desDecryption, desEncryption;
    private Cipher caRSADecryption;

    private Signature signMessage, verifyMessage;

    private final String DESKey = "abcdefghijklmackdlshdkqw";

    private BigInteger bobsMod, bobsPubExp;
    private BigInteger aliceMod, alicePrivateExp, alicePublicKey, p, q, orderOfN;
    private BigInteger caMOD, caPubExp;

    private SecretKey desKey;
    private IvParameterSpec initialVector;

    private RSAPublicKeySpec aPubSpec;
    private RSAPublicKeySpec caPubSpec;
    private RSAPrivateKeySpec aPrivSpec;

    private RSAPublicKey BobRSAPublic;
    private RSAPublicKey caRSAPublic;
    private RSAPrivateKey aliceRSAPrivate;

    private Socket connectionToHost;
    private TrustManagerFactory trustManagerFactory;
    private KeyManagerFactory keyManagerFactory;
    private KeyStore ks;
    private KeyStore trustedKeys;
    private SSLContext sslContext;
    private SSLEngine sslEngine;
    private SSLSocketFactory sslSocketFactory;
    private SSLSocket sslSocket;

    public Alice_Main() {
        try {
//            signMessage = Signature.getInstance("SHA256withRSA");
//            verifyMessage = Signature.getInstance("SHA256withRSA");
//            sslSocketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            System.setProperty("javax.net.ssl.trustStore","/Users/samgodfrey/cacerts.jks");

            System.setProperty("javax.net.ssl.trustStorePassword","dragon");

            verifyMessage = Signature.getInstance("SHA256withRSA");
            signMessage = Signature.getInstance("SHA256withRSA");

            sslContext = SSLContext.getInstance("TLS");
            trustManagerFactory = TrustManagerFactory.getInstance("SunX509");

            sslSocketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            ks = KeyStore.getInstance("JKS");
            trustedKeys = KeyStore.getInstance("JKS");

            ks.load(new FileInputStream("/Users/samgodfrey/keystore.jks"), "dragon".toCharArray());
            trustedKeys.load(new FileInputStream("/Users/samgodfrey/cacerts.jks"), "dragon".toCharArray());

            keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
            keyManagerFactory.init(ks,"dragon".toCharArray());

            trustManagerFactory = TrustManagerFactory.getInstance("SunX509");
            trustManagerFactory.init(trustedKeys);

            sslContext.init(keyManagerFactory.getKeyManagers(), null, null);

            sslSocketFactory = sslContext.getSocketFactory();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    public Alice_Main(boolean x){
        report = x;
        try {
            signMessage = Signature.getInstance("SHA256withRSA");
            verifyMessage = Signature.getInstance("SHA256withRSA");
            sslSocketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
        } catch (Exception e) {

        }
    }

    /* *******************************
    Here we need to import Bob's public key, ie d = e^-1 mod n
    where n and d are given. This will be called after the connection is setup.
    ****************************** */
    public void importPublicRSAKey(String modulus, String pubExp) {
        bobsMod = new BigInteger(modulus, 16);
        bobsPubExp = new BigInteger(pubExp);
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            aPubSpec = new RSAPublicKeySpec(bobsMod, bobsPubExp);
            BobRSAPublic = (RSAPublicKey) keyFactory.generatePublic(aPubSpec);

            rsaEncryption = Cipher.getInstance("RSA/ECB/NoPadding");
            rsaEncryption.init(Cipher.ENCRYPT_MODE, BobRSAPublic);
            System.out.println(BobRSAPublic.getPublicExponent());

        } catch (NoSuchAlgorithmException e) {

        } catch (NoSuchPaddingException e) {

        } catch (InvalidKeySpecException e) {

        } catch (InvalidKeyException e) {

        } catch (NumberFormatException e) {
            e.printStackTrace();
        }
        //byte[] cipherData = rsa.doFinal(text.getBytes());
    }

    /* *******************************
    Here we set up Alice's private key with imported numbers from openssl.
    This is done before connection.
   ****************************** */
    public void importPrivateRSAKey(String modulus, String privateExp) {
        aliceMod = new BigInteger(modulus, 16);
        alicePrivateExp = new BigInteger(privateExp, 16);
        alicePublicKey = new BigInteger("65537");
        System.out.println("Creating Private Key");
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            aPrivSpec = new RSAPrivateKeySpec(aliceMod, alicePrivateExp);
            aliceRSAPrivate = (RSAPrivateKey) keyFactory.generatePrivate(aPrivSpec);

            rsaDecrytpion = Cipher.getInstance("RSA/ECB/NoPadding");
            rsaDecrytpion.init(Cipher.DECRYPT_MODE, aliceRSAPrivate);
            signMessage.initSign(aliceRSAPrivate);

            if(report){
                System.out.println("Alice's Private Exponent:\r\n" +
                             bytesToHex(aliceRSAPrivate.getPrivateExponent().toByteArray()));
                System.out.println("Alice's Public Modulus:\r\n" +
                        bytesToHex(aliceRSAPrivate.getModulus().toByteArray()));

            }
            BigInteger aPr = aliceRSAPrivate.getPrivateExponent();
            System.out.println("Proof of Concept. ed = 1 mod |n|:\n"
                    + (alicePublicKey.multiply(aPr)).mod(orderOfN));

        } catch (NoSuchAlgorithmException e) {

        } catch (NoSuchPaddingException e) {

        } catch (InvalidKeySpecException e) {

        } catch (InvalidKeyException e) {

        }
    }

    /* *******************************
    Import numbers to help check that our encryption is working well. The order of n = (p-1)(q-1)
   ****************************** */
    public void setPrimes(String p1, String p2) {
        p = new BigInteger(p1, 16);
        q = new BigInteger(p2, 16);
        p = p.subtract(BigInteger.ONE);
        q = q.subtract(BigInteger.ONE);
        orderOfN = p.multiply(q);
    }

    /* *******************************
    Here we set up the public key of the CA imported numbers from openssl.
    This is done before connection.
   ****************************** */
    public void importCAPublicKey(String modulus, String pubExp) {
        caMOD = new BigInteger(modulus, 16);
        caPubExp = new BigInteger(pubExp, 16);
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            caPubSpec = new RSAPublicKeySpec(caMOD, caPubExp);
            caRSAPublic = (RSAPublicKey) keyFactory.generatePublic(caPubSpec);

            caRSADecryption = Cipher.getInstance("RSA/ECB/NoPadding");
            caRSADecryption.init(Cipher.DECRYPT_MODE, caRSAPublic);

            verifyMessage.initVerify(caRSAPublic);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
    }

    public void create3des() throws NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException {
        System.out.println("Creating 3des key");

        desDecryption = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        desEncryption = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        byte[] key = new byte[24];
        desKey = new SecretKeySpec(DESKey.getBytes(), "DESede");
        initialVector = new IvParameterSpec(new byte[8]);

        try {
            desDecryption.init(Cipher.DECRYPT_MODE, desKey, initialVector);
            desEncryption.init(Cipher.ENCRYPT_MODE, desKey, initialVector);
            if(report){
                System.out.println("DESKey:\r\n" + bytesToHex(desKey.getEncoded()));
                System.out.println("Initilization Vector:\r\n" + bytesToHex(initialVector.getIV()));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    public void connectToHost(String ipAddress, int x) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, InterruptedException, IOException, IllegalBlockSizeException, BadPaddingException {

        InetAddress ip = InetAddress.getByName(ipAddress);
        if(x == 1){
            sslSocket = (SSLSocket) sslSocketFactory.createSocket(ip, 9999);
            sslSocket.startHandshake();
        }
        else {
            connectionToHost = new Socket(ip, 9999);
        }

        DataOutputStream os = new DataOutputStream(sslSocket.getOutputStream());
        DataInputStream is = new DataInputStream(sslSocket.getInputStream());
        try {
            create3des();
        } catch (Exception e) {
            e.printStackTrace();
        }
        String initialRequest = "GET PUBLIC KEY\r\n";

        os.write(initialRequest.getBytes());
        os.flush();

        System.out.println("Waiting For Public Key");
        int keyLength = is.readInt();
        int hashLength = is.readInt();
        byte[] b = new byte[keyLength + hashLength];
        is.readFully(b);
        byte[] key = Arrays.copyOfRange(b, 0, keyLength);
        byte[] hash = Arrays.copyOfRange(b, keyLength, keyLength + hashLength);

        byte[] decryptedHash = caRSADecryption.doFinal(hash);
        verifyMessage.update(key);
        boolean auth = verifyMessage.verify(decryptedHash);

        RSAPublicKey bobsPublicKey = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(key));

        if(report){
            System.out.println("Bob's Public Key Recieved:\r\n" + bytesToHex(bobsPublicKey.getPublicExponent().toByteArray()));
            System.out.println("Bob's Public Modulus Recieved:\r\n" + bytesToHex(bobsPublicKey.getModulus().toByteArray()));

        }
        System.out.println("Bobs Public Key Verified: " + auth);


        rsaEncryption = Cipher.getInstance("RSA/ECB/NoPadding");
        rsaEncryption.init(Cipher.ENCRYPT_MODE, bobsPublicKey);
        signMessage.update(bobsPublicKey.getEncoded());

        byte[] c = signMessage.sign();
        os.write(c);
        if(report){
            System.out.println("Message Auth Sent: " + bytesToHex(c));
        }
        os.flush();
        communicationSession(os, is);
        System.out.println("Code Finished");
    }

    private void communicationSession(DataOutputStream os, DataInputStream is) throws BadPaddingException, IllegalBlockSizeException, IOException, SignatureException {
        System.out.println("Communication Session With Bob Initiated, Start Chatting!\r\nType exit to end session");
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));


        String message;
        while((message = br.readLine()) != null){
            if(!message.equals("exit")) {
        /* We have the message and need to create a tuple with:
            (3DES(message, signiture), RSA(3DES Key)). To Do this we are going to need to:
            1) Turn signiture into string and add it to message
         */
                wrapMessage(message.getBytes(), os);
            }
            else{
                os.writeInt(-1);
                break;
            }
        }
        sslSocket.close();
        System.out.println("Session Exited!");
    }

    private void wrapMessage(byte[] b, DataOutputStream os) {
        try {
            byte[] c = DESKey.getBytes("UTF-8");
            byte[] desKey = rsaEncryption.doFinal(c);
            signMessage.update(b);
            byte[] signiture = signMessage.sign();
            byte[] message = b;
            byte[] x = new byte[message.length + signiture.length];
            for(int i = 0; i < x.length; ++i){
                x[i] = i < message.length ? message[i] : signiture[i- message.length];
            }
            byte[] desMessage = desEncryption.doFinal(x);
            byte[] y = new byte[desMessage.length + desKey.length];
            for(int i = 0; i < y.length; ++i){
                y[i] = i < desMessage.length ? desMessage[i] : desKey[i- desMessage.length];
            }
            os.writeInt(y.length);
            os.writeInt(desMessage.length);
            os.writeInt(message.length);
            os.write(y);
            if(report){
                System.out.println("Message Sent:\r\n" + bytesToHex(b));
                System.out.println("Message Signiture Sent:\r\n" + bytesToHex(signiture));
                System.out.println("DES Encrypted Message Sent:\r\n" + bytesToHex(desMessage));
                System.out.println("RSA Encrypted DESKey Sent:\r\n" + bytesToHex(desKey));
            }
            System.out.println("Message Written");
        }catch(Exception e){
            e.printStackTrace();
        }
    }
    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }
}

