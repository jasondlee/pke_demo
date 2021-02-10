package com.steeplesoft.pke;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;

public class BaseClient {
    protected static final String ALGORITHM = "RSA";

    protected final String clientName;
    protected final String privateKeyFilename;
    protected final String publicKeyFilename;

    private Cipher cipher;
    private PrivateKey privateKey;
    private PublicKey publicKey;

    public BaseClient(String clientName) {
        this.clientName = clientName;
        privateKeyFilename = clientName + ".key";
        publicKeyFilename = clientName + "_pub.key";

        initialize();
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public String encryptText(String msg, Key key) {
        try {
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return Base64.getEncoder().encodeToString(cipher.doFinal(msg.getBytes("UTF-8")));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public String decryptText(String msg) {
        return decryptText(msg, privateKey);
    }

    public String decryptText(String msg, Key key) {
        try {
            cipher.init(Cipher.DECRYPT_MODE, key);
            return new String(cipher.doFinal(Base64.getDecoder().decode(msg)), "UTF-8");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    protected void initialize() {
        File privateKeyFile = new File(privateKeyFilename);
        File publicKeyFile = new File(publicKeyFilename);

        try {
            cipher = Cipher.getInstance(ALGORITHM);

            if (privateKeyFile.exists() || publicKeyFile.exists()) {
                loadKeys(privateKeyFile, publicKeyFile);
            } else {
                generateKeys();
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private void generateKeys() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
        keyGen.initialize(2048);
        KeyPair pair = keyGen.generateKeyPair();

        privateKey = pair.getPrivate();
        publicKey = pair.getPublic();

        writeToFile(privateKeyFilename, privateKey);
        writeToFile(publicKeyFilename, publicKey);
    }

    protected void loadKeys(File privateKeyFile, File publicKeyFile)
            throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        KeyFactory kf = KeyFactory.getInstance(ALGORITHM);

        privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(Files.readAllBytes(privateKeyFile.toPath())));
        publicKey = kf.generatePublic(new X509EncodedKeySpec(Files.readAllBytes(publicKeyFile.toPath())));
    }

    protected void writeToFile(String path, Key key) {
        try (FileOutputStream fos = new FileOutputStream(path)) {
            fos.write(key.getEncoded());
            fos.flush();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
