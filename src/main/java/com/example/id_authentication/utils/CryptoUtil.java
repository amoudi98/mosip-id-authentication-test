package com.example.id_authentication.utils;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import javax.crypto.*;
import java.security.*;

public class CryptoUtil {
    private static final String SYM_ALGORITHM = "AES";
    private static final int SYM_ALGORITHM_LENGTH = 256;
    private static BouncyCastleProvider bouncyCastleProvider;

    static {
        bouncyCastleProvider = addProvider();
    }

    private static BouncyCastleProvider addProvider() {
        BouncyCastleProvider bouncyCastleProvider = new BouncyCastleProvider();
        Security.addProvider(bouncyCastleProvider);
        return bouncyCastleProvider;
    }

    public static SecretKey genSecKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen;
        SecretKey secretKey = null;
        keyGen = KeyGenerator.getInstance(SYM_ALGORITHM, bouncyCastleProvider);
        keyGen.init(SYM_ALGORITHM_LENGTH, new SecureRandom());
        secretKey = keyGen.generateKey();
        return secretKey;
    }
}