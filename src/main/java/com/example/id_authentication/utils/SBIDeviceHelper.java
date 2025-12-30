package com.example.id_authentication.utils;

import org.springframework.core.env.Environment;
import org.springframework.stereotype.Service;
import java.io.FileInputStream;
import java.io.UnsupportedEncodingException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class SBIDeviceHelper {
    private final Environment env;
    private final FileUtils fileUtils;
    private final JwtUtility jwtUtility;

    public SBIDeviceHelper(Environment env, FileUtils fileUtils, JwtUtility jwtUtility){
        this.env = env;
        this.fileUtils = fileUtils;
        this.jwtUtility = jwtUtility;
    }

    private static final Map<String, PrivateKey> privateKeyMap = new ConcurrentHashMap<>();
    private static final Map<String, Certificate> certificateMap = new ConcurrentHashMap<>();

    public String signBiometricsData(String currentBioData) throws UnsupportedEncodingException {
        String keyStoreFileName = fileUtils.getFilePath(env.getProperty("mosip.partner.device.cert.path"));
        String keyAlias = env.getProperty("mosip.partner.device.cert.alias");
        String keyPwd = env.getProperty("mosip.partner.device.cert.password");


        return jwtUtility.getJwt(currentBioData.getBytes("UTF-8"),
                getPrivateKey(keyStoreFileName, keyAlias, keyPwd),
                (X509Certificate) getCertificate(keyStoreFileName, keyAlias, keyPwd));
    }

    public String signDigitalId(String digitalIdBase64) throws UnsupportedEncodingException {
        var keyStoreFileName = fileUtils.getFilePath(env.getProperty("mosip.partner.device.ftm.cert.path"));
        var keyAlias = env.getProperty("mosip.partner.device.ftm.cert.alias");
        var keyPwd = env.getProperty("mosip.partner.device.ftm.cert.password");

        return jwtUtility.getJwt(digitalIdBase64.getBytes("UTF-8"),
                getPrivateKey(keyStoreFileName, keyAlias, keyPwd),
                (X509Certificate) getCertificate(keyStoreFileName, keyAlias, keyPwd));
    }

    private PrivateKey getPrivateKey(String keyStoreFileName, String alias, String keystorePassword) {
        loadKeys(keyStoreFileName, alias, keystorePassword);
        return privateKeyMap.get(keyStoreFileName);
    }

    private Certificate getCertificate(String keyStoreFileName, String alias, String keystorePassword) {
        loadKeys(keyStoreFileName, alias, keystorePassword);
        return certificateMap.get(keyStoreFileName);
    }

    private void loadKeys(String keyStoreFileName, String alias, String keystorePassword) {
        if(privateKeyMap.containsKey(keyStoreFileName) && certificateMap.containsKey(keyStoreFileName)) {
            //LOGGER.info("Keystore already cached, nothing to load :: " + keystoreFilePath);
            return;
        }

        try(FileInputStream fileInputStream = new FileInputStream(keyStoreFileName)) {
            //LOGGER.info("Loading keystore into to local cache :: " + keystoreFilePath);
            KeyStore keystore = KeyStore.getInstance("PKCS12");
            keystore.load(fileInputStream, keystorePassword.toCharArray());

            privateKeyMap.put(keyStoreFileName, (PrivateKey)keystore.getKey(alias, keystorePassword.toCharArray()));
            certificateMap.put(keyStoreFileName, keystore.getCertificate(alias));
        } catch (Exception e) {
           // LOGGER.error("Failed to load keystore into local cache :: " + keystoreFilePath, e);
            throw new RuntimeException(e);
        }
    }
}