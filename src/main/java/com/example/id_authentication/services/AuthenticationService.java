package com.example.id_authentication.services;

import com.example.id_authentication.models.*;
import com.example.id_authentication.utils.CryptoUtility;
import com.example.id_authentication.utils.FileUtils;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.lang.JoseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Service;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.*;
import java.util.Map;
import java.util.Objects;

@Service
public class AuthenticationService {
    private static final Logger LOGGER = LoggerFactory.getLogger(AuthenticationService.class);
    private final Environment env;
    private final FileUtils fileUtils;
    private final CryptoUtility cryptoUtility;
    ObjectMapper mapper = new ObjectMapper();

    public AuthenticationService(Environment env, FileUtils fileUtils, CryptoUtility cryptoUtility){
        this.env = env;
        this.fileUtils = fileUtils;
        this.cryptoUtility = cryptoUtility;
    }

    public AuthenticationDataResult prepareAuthenticationData(AuthenticationParams authenticationParams) throws IOException, JoseException, UnrecoverableEntryException, CertificateException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        System.out.println("Preparing Auth Request...");
        AuthRequestDTO authRequestDTO = new AuthRequestDTO();

        authRequestDTO.setId(env.getProperty("authId"));
        authRequestDTO.setVersion(env.getProperty("specVersion"));
        authRequestDTO.setDomainUri(env.getProperty("domainUri"));
        authRequestDTO.setTransactionID(authenticationParams.getTransactionId());
        authRequestDTO.setRequestTime(CryptoUtility.getUTCCurrentDateTimeISOString());
        authRequestDTO.setConsentObtained(authenticationParams.getConsent());
        authRequestDTO.setIndividualId(authenticationParams.getIndividualId() + "@nin");
        authRequestDTO.setEnv(env.getProperty("env"));
        authRequestDTO.setIndividualIdType(authenticationParams.getIndividualIdType());

        AuthTypeDTO authTypeDTO = new AuthTypeDTO();
        authTypeDTO.setBio(isBioAuthType(authenticationParams.getAuthType()));
        authTypeDTO.setOtp(isOtpAuthType(authenticationParams.getAuthType()));
        authTypeDTO.setDemo(isDemoAuthType(authenticationParams.getAuthType()));
        authRequestDTO.setRequestedAuth(authTypeDTO);

        RequestDTO requestDTO = new RequestDTO();
        requestDTO.setTimestamp(CryptoUtility.getUTCCurrentDateTimeISOString());

        Map<String, Object> identityBlock = mapper.convertValue(requestDTO, Map.class);

        identityBlock.put("biometrics", authenticationParams.getBiometricData());

        LOGGER.info("Encrypting Auth Request...");

        EncryptionRequestDto encryptionRequestDto = new EncryptionRequestDto();
        encryptionRequestDto.setIdentityRequest(identityBlock);
        EncryptionResponseDto kernelEncrypt = null;
        try {
            kernelEncrypt = cryptoUtility.kernelEncrypt(encryptionRequestDto, false);
        } catch (Exception e) {
            e.printStackTrace();
            LOGGER.error("Encryption of Auth Request Failed");
            return AuthenticationDataResult.builder().build();
        }

        LOGGER.info("Authenticating...");

        authRequestDTO.setRequest(requestDTO);
        authRequestDTO.setThumbprint(kernelEncrypt.getThumbprint());

        Map<String, Object> authRequestMap = mapper.convertValue(authRequestDTO, Map.class);

        authRequestMap.replace("request", kernelEncrypt.getEncryptedIdentity());
        authRequestMap.replace("requestSessionKey", kernelEncrypt.getEncryptedSessionKey());
        authRequestMap.replace("requestHMAC", kernelEncrypt.getRequestHMAC());

        String reqJson = mapper.writeValueAsString(authRequestMap);
        var signature = getSignature(reqJson);

        return AuthenticationDataResult.builder()
                .authData(reqJson)
                .authSignature(signature)
                .build();
    }


    private boolean isBioAuthType(String authType) {
        return authType.equals("bio");
    }

    private boolean isOtpAuthType(String authType) {
        return authType.equals("otp");
    }

    private boolean isDemoAuthType(String authType) {
        return authType.equals("demo");
    }

    public boolean verifyDetachedJws(
            String detachedJws,
            String payload
    ) {
        try {
            var password = env.getProperty("mosip.partner.cert.password" , "QWEASD");
            var alias = env.getProperty("mosip.partner.cert.alias","1");
            // 1) Load the certificate from PKCS#12 keystore
            KeyStore ks = KeyStore.getInstance("PKCS12");
            try (FileInputStream fis = new FileInputStream(fileUtils.getFilePath(env.getProperty("mosip.partner.cert.path")))) {
                ks.load(fis, password.toCharArray());
            }
            X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
            if (cert == null) {
                throw new IllegalStateException("Certificate not found for alias: " + alias);
            }
            PublicKey publicKey = cert.getPublicKey();

            // 2) Prepare the JsonWebSignature object
            JsonWebSignature jws = new JsonWebSignature();
            // set the detached compact serialization (header..signature)
            jws.setCompactSerialization(detachedJws);
            // supply the payload out-of-band
            jws.setPayload(payload);
            // set the verification key
            jws.setKey(publicKey);
            // disable built-in validation of critical headers
            jws.setDoKeyValidation(false);

            // 3) Verify signature
            return jws.verifySignature();

        } catch (JoseException | java.security.KeyStoreException |
                 java.security.NoSuchAlgorithmException |
                 java.security.cert.CertificateException |
                 java.io.IOException e) {
            e.printStackTrace();
            return false;
        }
    }

    public String sign(String dataToSign, boolean includePayload,
                       boolean includeCertificate, boolean includeCertHash, String certificateUrl, String dirPath, String partnerId) throws JoseException, NoSuchAlgorithmException, UnrecoverableEntryException,
            KeyStoreException, CertificateException, IOException {

        JsonWebSignature jwSign = new JsonWebSignature();
        dirPath = fileUtils.getFilePath(env.getProperty("mosip.partner.cert.path"));
        KeyStore.PrivateKeyEntry keyEntry = getPrivateKeyEntryX(dirPath);

        if (Objects.isNull(keyEntry)) {
            throw new KeyStoreException("Key file not available for partner type: " + partnerId);
        }

        PrivateKey privateKey = keyEntry.getPrivateKey();

        X509Certificate x509Certificate = getCertificateEntry(dirPath, env.getProperty("mosip.partner.cert.alias"),env.getProperty("mosip.partner.cert.password"));

        if(x509Certificate == null) {
            x509Certificate = (X509Certificate) keyEntry.getCertificate();
        }

        if (includeCertificate)
            jwSign.setCertificateChainHeaderValue(new X509Certificate[] { x509Certificate });

        if (includeCertHash)
            jwSign.setX509CertSha256ThumbprintHeaderValue(x509Certificate);

        if (Objects.nonNull(certificateUrl))
            jwSign.setHeader("x5u", certificateUrl);

        jwSign.setPayload(dataToSign);
        jwSign.setAlgorithmHeaderValue("RS256");
        jwSign.setKey(privateKey);
        jwSign.setDoKeyValidation(false);
        if (includePayload)
            return jwSign.getCompactSerialization();

        return jwSign.getDetachedContentCompactSerialization();
    }

    public KeyStore.PrivateKeyEntry getPrivateKeyEntryX(String filePath) throws NoSuchAlgorithmException, UnrecoverableEntryException,
            KeyStoreException, IOException, CertificateException{
        Path path = Paths.get(filePath);
        var password = env.getProperty("mosip.partner.cert.password" , "QWEASD");
        var alias = env.getProperty("mosip.partner.cert.alias","1");
        if (Files.exists(path)){
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            try(InputStream p12FileStream = new FileInputStream(filePath)) {
                keyStore.load(p12FileStream, password.toCharArray());
                return (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, new KeyStore.PasswordProtection(password.toCharArray()));
            }
        }
        return null;
    }

    private X509Certificate getCertificateEntry(String keyStoreFileName, String alias, String keystorePassword) {
        try(FileInputStream fileInputStream = new FileInputStream(keyStoreFileName)) {
            KeyStore keystore = KeyStore.getInstance("PKCS12");
            keystore.load(fileInputStream, keystorePassword.toCharArray());

            return (X509Certificate) keystore.getCertificate(alias);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private String getSignature(String reqJson)
            throws KeyManagementException, NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException,
            CertificateException, JoseException, IOException {
        return sign(reqJson, false);
    }

    public String sign(String data, boolean isPayloadRequired)
            throws KeyManagementException, NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException,
            CertificateException, JoseException, IOException {
        return sign(data, false, true, false, null, "", "");
    }
}