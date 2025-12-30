package com.example.id_authentication.utils;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.xml.bind.DatatypeConverter;

public final class HMACUtils2 {
    private static final String HASH_ALGORITHM_NAME = "SHA-256";

    public static byte[] generateHash(byte[] bytes) throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        return messageDigest.digest(bytes);
    }

    public static String digestAsPlainTextWithSalt(byte[] password, byte[] salt) throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        messageDigest.update(password);
        messageDigest.update(salt);
        return DatatypeConverter.printHexBinary(messageDigest.digest());
    }

    public static String digestAsPlainText(byte[] bytes) throws NoSuchAlgorithmException {
        return DatatypeConverter.printHexBinary(generateHash(bytes)).toUpperCase();
    }

    public static byte[] generateSalt() {
        return generateSalt(16);
    }

    public static byte[] generateSalt(int bytes) {
        SecureRandom random = new SecureRandom();
        byte[] randomBytes = new byte[bytes];
        random.nextBytes(randomBytes);
        return randomBytes;
    }

    public static String encodeBase64String(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    public static byte[] decodeBase64(String data) {
        return Base64.getDecoder().decode(data);
    }

    private HMACUtils2() {
    }

    private static String encode(String password, byte[] salt) {
        int iterationCount = 27500;
        if (System.getenv("hashiteration") != null) {
            String envCount = System.getenv("hashiteration");
            if (Integer.parseInt(envCount) > iterationCount) {
                iterationCount = Integer.parseInt(envCount);
            }
        }

        KeySpec spec = new PBEKeySpec(password.toCharArray(), Base64.getDecoder().decode(salt), iterationCount, 512);

        try {
            byte[] key = getSecretKeyFactory().generateSecret(spec).getEncoded();
            return Base64.getEncoder().encodeToString(key);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException("Credential could not be encoded", e);
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    private static SecretKeyFactory getSecretKeyFactory() throws NoSuchAlgorithmException {
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("PBKDF2 algorithm not found", e);
        }
    }
}