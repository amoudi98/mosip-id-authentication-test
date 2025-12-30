package com.example.id_authentication.utils;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.security.spec.MGF1ParameterSpec;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.PSource.PSpecified;

import com.example.id_authentication.models.EncryptionRequestDto;
import com.example.id_authentication.models.EncryptionResponseDto;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Service;

@Service
public class CryptoUtility {
    private static BouncyCastleProvider provider;
    private static final String asymmetricAlgorithm = "RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING";
    private static final String SYMMETRIC_ALGORITHM = "AES/GCM/PKCS5Padding";
    private static final int GCM_TAG_LENGTH = 128;
    private static final String RSA_ECB_NO_PADDING = "RSA/ECB/NoPadding";
    private static final int AES_KEY_LENGTH = 256;
    private static final String MGF1 = "MGF1";
    private static final String AES = "AES";
    private static final String HASH_ALGO = "SHA-256";
    private static final int asymmetricKeyLength = 2048;
    private static final String UTC_DATETIME_PATTERN = "yyyy-MM-dd'T'HH:mm:ss'Z'";

    private final FileUtils fileUtils;
    private final Environment env;
    ObjectMapper mapper = new ObjectMapper();

    public CryptoUtility(FileUtils fileUtils, Environment env){
        this.fileUtils = fileUtils;
        this.env = env;
    }

    static {
        provider = init();
    }

    private static BouncyCastleProvider init() {
        BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.addProvider(provider);
        return provider;
    }

    public static byte[] generateHash(byte[] message, String algorithm) {
        byte[] hash = null;
        try {
            // Registering the Bouncy Castle as the RSA provider.
            MessageDigest digest = MessageDigest.getInstance(algorithm);
            digest.reset();
            hash = digest.digest(message);
        } catch (GeneralSecurityException ex) {
            ex.printStackTrace();
        }
        return hash;
    }

    public static String getUTCCurrentDateTimeISOString() {
        return formatToISOString2(ZonedDateTime.now(ZoneOffset.UTC).toLocalDateTime());
    }

    public static String formatToISOString2(LocalDateTime localDateTime) {
        return localDateTime.format(DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"));
    }

    public static String getTimestamp() {
        return formatToISOString(ZonedDateTime.now(ZoneOffset.UTC).toLocalDateTime());
    }

    public static String formatToISOString(LocalDateTime localDateTime) {
        return localDateTime.format(DateTimeFormatter.ofPattern(UTC_DATETIME_PATTERN));
    }

    public EncryptionResponseDto kernelEncrypt(EncryptionRequestDto encryptionRequestDto, boolean isInternal)
            throws Exception {
        EncryptionResponseDto encryptionResponseDto = new EncryptionResponseDto();
        String identityBlock = mapper.writeValueAsString(encryptionRequestDto.getIdentityRequest());

        SecretKey secretKey = CryptoUtil.genSecKey();

        byte[] encryptedIdentityBlock = symmetricEncryptForAuth(secretKey, identityBlock.getBytes(StandardCharsets.UTF_8),null);
        encryptionResponseDto.setEncryptedIdentity(org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(encryptedIdentityBlock));

        X509Certificate certificate = getCertificateFromFile(fileUtils.getFilePath(env.getProperty("mosip.ida.partner.cert.path")));
        PublicKey publicKey = certificate.getPublicKey();
        byte[] encryptedSessionKeyByte = asymmetricEncryptForAuth(publicKey ,(secretKey.getEncoded()));
        encryptionResponseDto.setEncryptedSessionKey(org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(encryptedSessionKeyByte));
        byte[] byteArr = symmetricEncryptForAuth(secretKey,HMACUtils2.digestAsPlainText(identityBlock.getBytes(StandardCharsets.UTF_8)).getBytes(),null);
        encryptionResponseDto.setRequestHMAC(org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(byteArr));

        String thumbprint = Hex.encodeHexString(getCertificateThumbprint(certificate));
        encryptionResponseDto.setThumbprint(thumbprint);
        return encryptionResponseDto;
    }

    private X509Certificate getCertificateFromFile(String filePath) throws CertificateException, IOException {
        try (InputStream inStream = new FileInputStream(filePath)) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(inStream);
        }
    }

    private byte[] getCertificateThumbprint(Certificate cert) throws CertificateEncodingException {
        return DigestUtils.sha256(cert.getEncoded());
    }

    public static Map<String, String>  encrypt(PublicKey publicKey, byte[] dataBytes, String transactionId) {

        Map<String, String> result = new HashMap<>();
        try {
            String timestamp =  getTimestamp();
            byte[] xorResult = getXOR(timestamp, transactionId);

            byte[] aadBytes = getLastBytes(xorResult, 16);
            byte[] ivBytes = getLastBytes(xorResult, 12);

            SecretKey secretKey = getSymmetricKey();
            final byte[] encryptedData = symmetricEncrypt(secretKey, dataBytes, ivBytes, aadBytes);
            final byte[] encryptedSymmetricKey =  asymmetricEncrypt(publicKey, secretKey.getEncoded());

            result.put("ENC_SESSION_KEY", StringHelper.base64UrlEncode(encryptedSymmetricKey));
            result.put("ENC_DATA", StringHelper.base64UrlEncode(encryptedData));
            result.put("TIMESTAMP", timestamp);

        } catch(Exception ex) {
            ex.printStackTrace();
        }
        return result;
    }

    public byte[] asymmetricEncryptForAuth(PublicKey key, byte[] data) throws Exception {
        //Objects.requireNonNull(key, SecurityExceptionCodeConstant.MOSIP_INVALID_KEY_EXCEPTION.getErrorMessage());
        //CryptoUtils.verifyData(data);

        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance(asymmetricAlgorithm);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException e) {
            //throw new io.mosip.kernel.core.exception.NoSuchAlgorithmException(SecurityExceptionCodeConstant.MOSIP_NO_SUCH_ALGORITHM_EXCEPTION.getErrorCode(), SecurityExceptionCodeConstant.MOSIP_NO_SUCH_ALGORITHM_EXCEPTION.getErrorMessage(), e);
        }

        OAEPParameterSpec oaepParams = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSpecified.DEFAULT);

        try {
            cipher.init(1, key, oaepParams);
        } catch (InvalidKeyException e) {
           // throw new io.mosip.kernel.core.crypto.exception.InvalidKeyException(SecurityExceptionCodeConstant.MOSIP_INVALID_KEY_EXCEPTION.getErrorCode(), e.getMessage(), e);
        } catch (InvalidAlgorithmParameterException e) {
           // throw new InvalidParamSpecException(SecurityExceptionCodeConstant.MOSIP_INVALID_PARAM_SPEC_EXCEPTION.getErrorCode(), SecurityExceptionCodeConstant.MOSIP_INVALID_PARAM_SPEC_EXCEPTION.getErrorMessage(), e);
        }

        return this.doFinal(data, cipher);
    }

    public byte[] symmetricEncryptForAuth(SecretKey key, byte[] data, byte[] aad) {
        //Objects.requireNonNull(key, SecurityExceptionCodeConstant.MOSIP_INVALID_KEY_EXCEPTION.getErrorMessage());
        //CryptoUtils.verifyData(data);

        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance(SYMMETRIC_ALGORITHM);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException e) {
            //throw new io.mosip.kernel.core.exception.NoSuchAlgorithmException(SecurityExceptionCodeConstant.MOSIP_NO_SUCH_ALGORITHM_EXCEPTION.getErrorCode(), SecurityExceptionCodeConstant.MOSIP_NO_SUCH_ALGORITHM_EXCEPTION.getErrorMessage(), e);
        }

        byte[] output = null;
        byte[] randomIV = this.generateIV(cipher.getBlockSize());

        try {
            SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), "AES");
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, randomIV);
            cipher.init(1, keySpec, gcmParameterSpec);
            output = new byte[cipher.getOutputSize(data.length) + cipher.getBlockSize()];
            if (aad != null && aad.length != 0) {
                cipher.updateAAD(aad);
            }

            byte[] processData = this.doFinal(data, cipher);
            System.arraycopy(processData, 0, output, 0, processData.length);
            System.arraycopy(randomIV, 0, output, processData.length, randomIV.length);
            return output;
        } catch (InvalidKeyException e) {
           //throw new io.mosip.kernel.core.crypto.exception.InvalidKeyException(SecurityExceptionCodeConstant.MOSIP_INVALID_KEY_EXCEPTION.getErrorCode(), SecurityExceptionCodeConstant.MOSIP_INVALID_KEY_EXCEPTION.getErrorMessage(), e);
        } catch (InvalidAlgorithmParameterException e) {
           //throw new io.mosip.kernel.core.crypto.exception.InvalidKeyException(SecurityExceptionCodeConstant.MOSIP_INVALID_PARAM_SPEC_EXCEPTION.getErrorCode(), SecurityExceptionCodeConstant.MOSIP_INVALID_PARAM_SPEC_EXCEPTION.getErrorMessage(), e);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        return new byte[0];
    }

    private byte[] generateIV(int blockSize) {
        var secureRandom = new SecureRandom();
        byte[] byteIV = new byte[blockSize];
        secureRandom.nextBytes(byteIV);
        return byteIV;
    }

    public static String decrypt(PrivateKey privateKey, String sessionKey, String data, String timestamp,
                                 String transactionId) {
        try {

            timestamp = timestamp.trim();
            byte[] xorResult = getXOR(timestamp, transactionId);
            byte[] aadBytes = getLastBytes(xorResult, 16);
            byte[] ivBytes = getLastBytes(xorResult, 12);

            byte[] decodedSessionKey =  StringHelper.base64UrlDecode(sessionKey);
            final byte[] symmetricKey = asymmetricDecrypt(privateKey, decodedSessionKey);
            SecretKeySpec secretKeySpec = new SecretKeySpec(symmetricKey, "AES");

            byte[] decodedData =  StringHelper.base64UrlDecode(data);
            final byte[] decryptedData = symmetricDecrypt(secretKeySpec, decodedData, ivBytes, aadBytes);
            return new String(decryptedData);

        } catch(Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }

    public static byte[] symmetricDecrypt(SecretKeySpec secretKeySpec, byte[] dataBytes, byte[] ivBytes, byte[] aadBytes) {
        try {
            Cipher cipher = Cipher.getInstance(SYMMETRIC_ALGORITHM);
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, ivBytes);
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, gcmParameterSpec);
            cipher.updateAAD(aadBytes);
            return cipher.doFinal(dataBytes);
        } catch(Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }

    public static byte[] symmetricEncrypt(SecretKey secretKey, byte[] data, byte[] ivBytes, byte[] aadBytes) {
        try {
            Cipher cipher = Cipher.getInstance(SYMMETRIC_ALGORITHM);
            SecretKeySpec keySpec = new SecretKeySpec(secretKey.getEncoded(), "AES");
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, ivBytes);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmParameterSpec);
            cipher.updateAAD(aadBytes);
            return cipher.doFinal(data);

        } catch(Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }



    public static SecretKey getSymmetricKey() throws NoSuchAlgorithmException {
        KeyGenerator generator = KeyGenerator.getInstance(AES, provider);
        SecureRandom random = new SecureRandom();
        generator.init(AES_KEY_LENGTH, random);
        return generator.generateKey();
    }

    public static byte[] asymmetricEncrypt(PublicKey key, byte[] data) throws Exception {

        Cipher cipher = Cipher.getInstance(asymmetricAlgorithm);

        final OAEPParameterSpec oaepParams = new OAEPParameterSpec(HASH_ALGO, MGF1, MGF1ParameterSpec.SHA256,
                PSpecified.DEFAULT);
        cipher.init(Cipher.ENCRYPT_MODE, key, oaepParams);
        return doFinal(data, cipher);
    }

// Option 1: Using Bouncy Castle OAEP implementation (Recommended)
    public static byte[] asymmetricDecrypt(PrivateKey key, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_ECB_NO_PADDING);
        cipher.init(Cipher.DECRYPT_MODE, key);

        byte[] paddedPlainText = doFinal(data, cipher);
        if (paddedPlainText.length < asymmetricKeyLength / 8) {
            byte[] tempPipe = new byte[asymmetricKeyLength / 8];
            System.arraycopy(paddedPlainText, 0, tempPipe, tempPipe.length - paddedPlainText.length,
                    paddedPlainText.length);
            paddedPlainText = tempPipe;
        }
        final OAEPParameterSpec oaepParams = new OAEPParameterSpec(HASH_ALGO, MGF1, MGF1ParameterSpec.SHA256,
                PSpecified.DEFAULT);
        return unpadOEAPPadding(paddedPlainText, oaepParams, key);
    }

    // Option 1: Using Bouncy Castle for OAEP unpadding
    private static byte[] unpadOEAPPadding(byte[] paddedPlainText, OAEPParameterSpec paramSpec, PrivateKey privateKey) throws Exception {
        try {
            // Convert Java PrivateKey to Bouncy Castle format
            RSAPrivateCrtKeyParameters bcPrivateKey = (RSAPrivateCrtKeyParameters) PrivateKeyFactory.createKey(privateKey.getEncoded());

            // Create OAEP cipher with SHA-256 digest
            AsymmetricBlockCipher cipher = new OAEPEncoding(new RSAEngine(), new SHA256Digest());
            cipher.init(false, bcPrivateKey); // false for decryption

            return cipher.processBlock(paddedPlainText, 0, paddedPlainText.length);
        } catch (Exception e) {
            throw new Exception("OAEP unpadding failed: " + e.getMessage(), e);
        }
    }

    private static byte[] doFinal(byte[] data, Cipher cipher) throws Exception {
        return cipher.doFinal(data);
    }

    // Function to insert n 0s in the
    // beginning of the given string
    static byte[] prependZeros(byte[] str, int n) {
        byte[] newBytes = new byte[str.length + n];
        int i = 0;
        for (; i < n; i++) {
            newBytes[i] = 0;
        }

        for(int j = 0;i < newBytes.length; i++, j++) {
            newBytes[i] = str[j];
        }

        return newBytes;
    }

    // Function to return the XOR
    // of the given strings
    private static byte[] getXOR(String a, String b) {
        byte[] aBytes = a.getBytes();
        byte[] bBytes = b.getBytes();
        // Lengths of the given strings
        int aLen = aBytes.length;
        int bLen = bBytes.length;
        // Make both the strings of equal lengths
        // by inserting 0s in the beginning
        if (aLen > bLen) {
            bBytes = prependZeros(bBytes, aLen - bLen);
        } else if (bLen > aLen) {
            aBytes = prependZeros(aBytes, bLen - aLen);
        }
        // Updated length
        int len = Math.max(aLen, bLen);
        byte[] xorBytes = new byte[len];

        // To store the resultant XOR
        for (int i = 0; i < len; i++) {
            xorBytes[i] = (byte)(aBytes[i] ^ bBytes[i]);
        }
        return xorBytes;
    }

    private static byte[] getLastBytes(byte[] xorBytes, int lastBytesNum) {
        assert(xorBytes.length >= lastBytesNum);
        return Arrays.copyOfRange(xorBytes, xorBytes.length - lastBytesNum, xorBytes.length);
    }

//    public static void main(String[] args) throws Exception {
//        String data = "this is my test";
//
//        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
//        gen.initialize(2048);
//        KeyPair pair = gen.generateKeyPair();
//
//        String timestamp =  getTimestamp();
//        String transactionId = "sdfsdf-sdfsd";
//        byte[] xorResult = getXOR(timestamp, transactionId);
//        byte[] aadBytes = getLastBytes(xorResult, 16);
//        byte[] ivBytes = getLastBytes(xorResult, 12);
//        byte[] dataBytes = data.getBytes();
//
//        SecretKey secretKey = getSymmetricKey();
//        final byte[] encryptedData = symmetricEncrypt(secretKey, dataBytes, ivBytes, aadBytes);
//        final byte[] encryptedSymmetricKey =  asymmetricEncrypt(pair.getPublic(), secretKey.getEncoded());
//
//        String bioValue = StringHelper.base64UrlEncode(encryptedData);
//        String sessionKey = StringHelper.base64UrlEncode(encryptedSymmetricKey);
//
//        byte[] decodedSessionKey =  StringHelper.base64UrlDecode(sessionKey);
//        final byte[] symmetricKey = asymmetricDecrypt(pair.getPrivate(), decodedSessionKey);
//        SecretKeySpec secretKeySpec = new SecretKeySpec(symmetricKey, "AES");
//
//        byte[] decodedBioValue =  StringHelper.base64UrlDecode(bioValue);
//        final byte[] decryptedData = symmetricDecrypt(secretKeySpec, decodedBioValue, ivBytes, aadBytes);
//        System.out.println(new String(decryptedData));
//    }
}