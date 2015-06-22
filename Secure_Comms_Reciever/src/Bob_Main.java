/**
 * Created by samgodfrey on 4/17/15.
 */

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.*;
import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.*;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.cert.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.*;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;

public class Bob_Main {
    final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();

    private boolean report, ssl;
    private ServerSocket server;
    private Socket connectedSocket;

    private Cipher rsaEncryption;
    private Cipher rsaDecrytpion;
    private Cipher caRSAEncryption;
    private Cipher desEncryption, desDecryption;

    private final String DESKey = "abcdefghijklmackdlshdkqw";

    private Signature verifyMessage, signMessage;

    private BigInteger bobsMod, bobsPrivExp;
    private BigInteger bobsPublicMod, bobsPubExp, p, q, orderOfN;
    ;
    private BigInteger alicePublicMod, alicePublicExp;
    private BigInteger caMOD, caPrivExp;

    private SecretKey desKey;
    private IvParameterSpec initialVector;

    private RSAPublicKeySpec aPubSpec, aPubSpec1;
    private RSAPrivateKeySpec caPrivSpec;
    private RSAPrivateKeySpec aPrivSpec;

    private RSAPublicKey bobsRSAPublic, aliceRSAPublic;
    private RSAPrivateKey caRSAPrivate;
    private RSAPrivateKey bobsRSAPrivate;

    private TrustManagerFactory trustManagerFactory;
    private KeyManagerFactory keyManagerFactory;
    private KeyStore ks;
    private KeyStore trustedKeys;
    private SSLContext sslContext;
    private SSLEngine sslEngine;
    private SSLServerSocketFactory sslServerSocketFactory;
    private SSLServerSocket sslServerSocket;
    private SSLSocket sslSocket;


    public Bob_Main() {
        try {
//            verifyMessage = Signature.getInstance("SHA256withRSA");
//            signMessage = Signature.getInstance("SHA256withRSA");
//            sslContext = SSLContext.getInstance("TLS");
//            trustManagerFactory = TrustManagerFactory.getInstance("SunX509");
//            sslServerSocketFactory = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
//            ks = KeyStore.getInstance("JKS");
//            trustedKeys = KeyStore.getInstance("JKS");
//            ks.load(new FileInputStream("/Users/samgodfrey/keystore.jks"), "dragon".toCharArray());
//            trustedKeys.load(new FileInputStream("/Users/samgodfrey/cacerts.jks"), "dragon".toCharArray());
//            keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
//            keyManagerFactory.init(ks,"dragon".toCharArray());
//            trustManagerFactory = TrustManagerFactory.getInstance("SunX509");
//            trustManagerFactory.init(trustedKeys);
//            sslContext.init(keyManagerFactory.getKeyManagers(), null, null);
//
//            sslServerSocketFactory = sslContext.getServerSocketFactory();


            signMessage = Signature.getInstance("SHA256withRSA");
            verifyMessage = Signature.getInstance("SHA256withRSA");

        } catch (NoSuchAlgorithmException e) {

        }
//        catch (KeyStoreException e){
//            e.printStackTrace();
//        }
//        catch (FileNotFoundException e){
//            e.printStackTrace();
//        }
//        catch (IOException e){
//            e.printStackTrace();
//        } catch (CertificateException e){
//            e.printStackTrace();
//        }
//          catch (UnrecoverableKeyException e){
//            e.printStackTrace();
//        } catch (KeyManagementException e){
//            e.printStackTrace();
//        }
        catch (NullPointerException e){
            e.printStackTrace();
        }

    }
    public Bob_Main(boolean x){
        report = x;
        try {
            verifyMessage = Signature.getInstance("SHA256withRSA");
            signMessage = Signature.getInstance("SHA256withRSA");
            sslServerSocketFactory = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
        } catch (NoSuchAlgorithmException e) {

        }
    }

    public void startClient() throws SignatureException, IOException, IllegalBlockSizeException, BadPaddingException, InterruptedException {

        if(ssl) {
            System.out.println("Creating SSL Socket...");
//            sslEngine = sslContext.createSSLEngine();
            sslServerSocket = (SSLServerSocket) sslServerSocketFactory.createServerSocket(9999);
            sslSocket = (SSLSocket) sslServerSocket.accept();
        }
        else {
            server = new ServerSocket(9999);

            connectedSocket = server.accept();
        }
        try {
            create3des();

        } catch (Exception e) {
            e.printStackTrace();
        }
        DataInputStream is = new DataInputStream(connectedSocket.getInputStream());
        DataOutputStream os = new DataOutputStream(connectedSocket.getOutputStream());

        BufferedReader br = new BufferedReader(new InputStreamReader(is));
        String line = br.readLine();

        System.out.println(line);
        if (line.equals("GET PUBLIC KEY")) {

            System.out.println("Reuquest For Public Key Recieved, Sending Public Key...");

            verifyMessage.update(bobsRSAPublic.getEncoded());
            signMessage.update(bobsRSAPublic.getEncoded());

            byte[] key = bobsRSAPublic.getEncoded();

            byte[] hash = signMessage.sign();
            byte[] signedhash = caRSAEncryption.doFinal(hash);

            byte[] x = new byte[key.length + signedhash.length];
            for (int i = 0; i < x.length; ++i) {
                x[i] = i < key.length ? key[i] : signedhash[i - key.length];
            }
            os.writeInt(key.length);
            os.writeInt(signedhash.length);
            os.write(x);

        }
        System.out.println("Recieving Message Auth...");
        byte[] ccc = new byte[128];
        is.readFully(ccc);

        System.out.println("Checking Message Auth With SHA-256...");
        if(report){
            System.out.println("Message Auth Recieved: " + bytesToHex(ccc));
        }

        boolean auth = verifyMessage.verify(ccc);
        System.out.println("Message Auth: " + auth);
        communictionSession(os, is);
    }

    public void setPrimes(String p1, String p2) {
        p = new BigInteger(p1, 16);
        q = new BigInteger(p2, 16);
        p = p.subtract(BigInteger.ONE);
        q = q.subtract(BigInteger.ONE);
        orderOfN = p.multiply(q);
        orderOfN = orderOfN.subtract(BigInteger.ONE);
    }

    public void importPublicRSAKeyForBob(String modulus, String pubExp) {
        bobsPublicMod = new BigInteger(modulus, 16);
        bobsPubExp = new BigInteger(pubExp);

        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            aPubSpec = new RSAPublicKeySpec(bobsPublicMod, bobsPubExp);
            bobsRSAPublic = (RSAPublicKey) keyFactory.generatePublic(aPubSpec);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (NullPointerException e) {
            e.printStackTrace();
        }
    }

    public void importPublicRSAKeyForAlice(String modulus, String pubExp) {
        alicePublicMod = new BigInteger(modulus, 16);
        alicePublicExp = new BigInteger(pubExp);
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            aPubSpec1 = new RSAPublicKeySpec(alicePublicMod, alicePublicExp);
            aliceRSAPublic = (RSAPublicKey) keyFactory.generatePublic(aPubSpec1);

            rsaEncryption = Cipher.getInstance("RSA/ECB/NoPadding");
            rsaEncryption.init(Cipher.ENCRYPT_MODE, bobsRSAPublic);

            verifyMessage.initVerify(aliceRSAPublic);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NullPointerException e) {
            e.printStackTrace();
        }

    }

    public void importPrivateRSAKey(String modulus, String privateExp) {
        bobsMod = new BigInteger(modulus, 16);
        bobsPrivExp = new BigInteger(privateExp, 16);
        System.out.println("Creating Private Key");
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            aPrivSpec = new RSAPrivateKeySpec(bobsMod, bobsPrivExp);
            bobsRSAPrivate = (RSAPrivateKey) keyFactory.generatePrivate(aPrivSpec);
            rsaDecrytpion = Cipher.getInstance("RSA/ECB/NoPadding");
            rsaDecrytpion.init(Cipher.DECRYPT_MODE, bobsRSAPrivate);
            if(report) {
                System.out.println("Bob's Private Exponent:\r\n" + bytesToHex(bobsRSAPrivate.getPrivateExponent().toByteArray()) +
                        "\r\nBob's Public Modulus:\r\n" + bytesToHex(bobsRSAPrivate.getModulus().toByteArray()));
            }

        } catch (NoSuchAlgorithmException e) {

        } catch (NoSuchPaddingException e) {

        } catch (InvalidKeySpecException e) {

        } catch (InvalidKeyException e) {

        }
    }

    public void importCAPrivateKey(String modulus, String privExp) {
        caMOD = new BigInteger(modulus, 16);
        caPrivExp = new BigInteger(privExp, 16);
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            caPrivSpec = new RSAPrivateKeySpec(caMOD, caPrivExp);
            caRSAPrivate = (RSAPrivateKey) keyFactory.generatePrivate(caPrivSpec);

            caRSAEncryption = Cipher.getInstance("RSA/ECB/NoPadding");
            caRSAEncryption.init(Cipher.ENCRYPT_MODE, caRSAPrivate);

            signMessage.initSign(caRSAPrivate);
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

        desEncryption = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        desDecryption = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        byte[] key = new byte[24];
        desKey = new SecretKeySpec(DESKey.getBytes(), "DESede");
        initialVector = new IvParameterSpec(new byte[8]);

        try {
            desEncryption.init(Cipher.ENCRYPT_MODE, desKey, initialVector);
            desDecryption.init(Cipher.DECRYPT_MODE, desKey, initialVector);
            if(report){
                System.out.println("DESKey:\r\n" + bytesToHex(desKey.getEncoded()));
                System.out.println("Initilization Vector:\r\n" + bytesToHex(initialVector.getIV()));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    public void communictionSession(DataOutputStream os, DataInputStream is) throws IllegalBlockSizeException, BadPaddingException, SignatureException, IOException {

        System.out.println("Communication Session Started...");
        while (sslSocket.isConnected()) {
            int totalLength;
            if ((totalLength = is.readInt()) == -1) {
                System.out.println("Session Closed On Other Side");
                break;
            }
            int desMessageLength = is.readInt();
            int messageLength = is.readInt();
            byte[] message = new byte[totalLength];
            is.readFully(message);

            byte[] desMes = new byte[desMessageLength];
            byte[] rsaSig = new byte[totalLength - desMessageLength];
            byte[] plaintext = new byte[messageLength];
            byte[] mesSig = new byte[desMessageLength - messageLength];

            desMes = Arrays.copyOfRange(message, 0, desMessageLength);
            rsaSig = Arrays.copyOfRange(message, desMessageLength, totalLength);
            if(report){
                System.out.println("DES Encrypted Message Recieved:\r\n" +
                        bytesToHex(desMes));
                System.out.println("RSA Encrypted DESKey Recieved:\r\n" +
                        bytesToHex(rsaSig));
            }

            byte[] b = desDecryption.doFinal(desMes);
            byte[] decryptedDESkey = rsaDecrytpion.doFinal(rsaSig);


            plaintext = Arrays.copyOfRange(b, 0, messageLength);
            mesSig = Arrays.copyOfRange(b, messageLength, desMessageLength);

            int z = mesSig.length - 1;
            while (z >= 0 && mesSig[z] == 0) {
                --z;
            }
            mesSig = Arrays.copyOfRange(mesSig, 0, z + 1);

            int zz = decryptedDESkey.length - 1;
            while (zz >= 0 && decryptedDESkey[z] == 0) {
                --zz;
            }
            decryptedDESkey = Arrays.copyOfRange(decryptedDESkey, 0, zz + 1);

            if(report){
                System.out.println("DES Decrypted Message:\r\n" +
                        bytesToHex(plaintext));
                System.out.println("DES Decrypted Message Hash:\r\n" +
                        bytesToHex(mesSig));
                System.out.println("RSA Encyrpted DESKey:\r\n" +
                        bytesToHex(rsaSig));
            }
            String stringplaintext = new String(plaintext, "UTF-8");
            System.out.println("Updating SHA256 Signiture...");
            verifyMessage.update(plaintext);

            System.out.println("Text Recieved: " + stringplaintext);
            System.out.println("Message Auth: "+ verifyMessage.verify(mesSig));

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
