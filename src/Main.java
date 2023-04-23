import generator.RSAKeyPairGenerator;
import key.KeyPair;
import key.PrivateKey;
import key.PublicKey;
import signature.RSASignature;
import signature.Signature;

import java.security.SecureRandom;
//import signature.DSASignature;
//import signature.ECDSANewSignature;
//import signature.ECDSASignature;
//import signature.ElgamalSignature;
//import signature.RSASignature;

//import static signature.RSASignature.padOEAP;

public class Main {
    public static void main(String[] args) throws Exception {
        String message = "Hello, world!";

        // Generate RSA key pair
        RSAKeyPairGenerator keyGen = new RSAKeyPairGenerator();
        keyGen.initialize(3072, new SecureRandom());
        KeyPair keyPair = keyGen.generateKeyPair();

        // Get the private and public keys
        PrivateKey privateKey = keyPair.getPrivateKey();
        PublicKey publicKey = keyPair.getPublicKey();

        // Sign the message with the private key
        Signature signature = new RSASignature();
        signature.initSign(privateKey);
        signature.update(message.getBytes());
        byte[] signatureBytes = signature.sign();

        // Verify the signature with the public key
        signature.initVerify(publicKey);
        signature.update(message.getBytes());
        boolean verified = signature.verify(signatureBytes);

        System.out.println(verified);

//        String message = "Hello, world!";
//
//        // Generate RSA key pair
//        ElgamalKeypairGenerator keyGen = new ElgamalKeypairGenerator();
//        keyGen.initialize(1024);
//        KeyPair keyPair = keyGen.generateKeyPair();
//
//        // Get the private and public keys
//        PrivateKey privateKey = keyPair.getPrivateKey();
//        PublicKey publicKey = keyPair.getPublicKey();
//
//        // Sign the message with the private key
//        Signature signature = new ElgamalSignature();
//        signature.initSign(privateKey);
//        signature.update(message.getBytes());
//        byte[] signatureBytes = signature.sign();
//
//        // Verify the signature with the public key
//        signature.initVerify(publicKey);
//        signature.update(message.getBytes());
//        boolean verified = signature.verify(signatureBytes);
//
//        System.out.println(verified);

//        ECDSAKeyPairGenerator keyGen = new ECDSAKeyPairGenerator(EllipticCurveArithmetics.createFrom(SECP.SECP256R1));
//        KeyPair keyPair = keyGen.generateKeyPair();
//        // Get the private and public keys
//        PrivateKey privateKey = keyPair.getPrivateKey();
//        PublicKey publicKey = keyPair.getPublicKey();
//
//        // Sign the message with the private key
//        String message = "Hello";
//        ECDSANewSignature signature = new ECDSANewSignature();
//        signature.initialize(new MPMStandardBehavior(EllipticCurveArithmetics.createFrom(SECP.SECP256R1)));
//        signature.initSign(privateKey);
//        signature.update(message.getBytes());
//        byte[] signatureBytes = signature.sign();
//
//        // Verify the signature with the public key
//        signature.initVerify(publicKey);
//        signature.update(message.getBytes());
//        boolean verified = signature.verify(signatureBytes);
//
//        System.out.println(verified);

//        String message = "Hello, world!";
//
//        // Generate RSA key pair
//        DSAKeyPairGenerator keyGen = new DSAKeyPairGenerator();
//        KeyPair keyPair = keyGen.generateKeyPair();
//
//        // Get the private and public keys
//        PrivateKey privateKey = keyPair.getPrivateKey();
//        PublicKey publicKey = keyPair.getPublicKey();
//
//        // Sign the message with the private key
//        Signature signature = new DSASignature();
//        signature.initSign(privateKey);
//        signature.update(message.getBytes());
//        byte[] signatureBytes = signature.sign();
//
//        // Verify the signature with the public key
//        signature.initVerify(publicKey);
//        signature.update(message.getBytes());
//        boolean verified = signature.verify(signatureBytes);
//
//        System.out.println(verified);
    }
}