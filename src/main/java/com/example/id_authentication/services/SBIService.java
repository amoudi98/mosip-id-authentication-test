package com.example.id_authentication.services;

import com.example.id_authentication.constants.SBIConstant;
import com.example.id_authentication.models.*;
import com.example.id_authentication.utils.CryptoUtility;
import com.example.id_authentication.utils.JwtUtility;
import com.example.id_authentication.utils.SBIDeviceHelper;
import com.example.id_authentication.utils.StringHelper;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonGenerationException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.jose4j.json.internal.json_simple.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Service;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Map;

@Service
public class SBIService {
    private static final Logger LOGGER = LoggerFactory.getLogger(SBIService.class);

    private final SBIDeviceHelper deviceHelper;
    private final Environment env;
    private final JwtUtility jwtUtility;

    SBIService(SBIDeviceHelper deviceHelper, Environment env, JwtUtility jwtUtility) {
        this.deviceHelper = deviceHelper;
        this.env = env;
        this.jwtUtility = jwtUtility;
    }

    public BioMetricsDto getBiometricData (String transactionId, CaptureRequestDto requestObject,
                                           String previousHash, String bioType, String bioSubType, String bioValue,
                                           int qualityScore, int qualityRequestScore, boolean isUsedForAuthenication) throws  JsonGenerationException, JsonMappingException, IOException, DecoderException, NoSuchAlgorithmException
    {
        DeviceInfo deviceInfo = getDeviceInfo(bioType);

        BioMetricsDto biometric = new BioMetricsDto ();
        biometric.setSpecVersion(requestObject.getSpecVersion());

        BioMetricsDataDto biometricData = new BioMetricsDataDto ();
        biometricData.setDeviceCode(deviceInfo.getDeviceCode());
        biometricData.setDigitalId(deviceInfo.getDigitalId());
        biometricData.setDeviceServiceVersion(deviceInfo.getServiceVersion());
        biometricData.setBioType(bioType);
        biometricData.setBioSubType(bioSubType);
        biometricData.setPurpose(requestObject.getPurpose());
        biometricData.setEnv(requestObject.getEnv());

        if (isUsedForAuthenication)
            biometricData.setDomainUri(requestObject.getDomainUri() + "");

        if (isUsedForAuthenication == false)
        {
            biometricData.setBioValue(bioValue);
            biometricData.setTimestamp(CryptoUtility.getTimestamp());
        }
        else
        {
            try {
                X509Certificate certificate = jwtUtility.getCertificateToEncryptCaptureBioValue();
                PublicKey publicKey = certificate.getPublicKey();
                LOGGER.info("Start Encrypting BIO Data ...");
                Map<String, String> cryptoResult = CryptoUtility.encrypt(publicKey,
                        StringHelper.base64UrlDecode(bioValue), transactionId);

                biometricData.setTimestamp(cryptoResult.get("TIMESTAMP"));
                biometricData.setBioValue(cryptoResult.containsKey("ENC_DATA") ?
                        cryptoResult.get("ENC_DATA") : null);
                biometric.setSessionKey(cryptoResult.get("ENC_SESSION_KEY"));
                String thumbPrint = toHex (jwtUtility.getCertificateThumbprint(certificate)).replace ("-", "").toUpperCase();
                biometric.setThumbprint(thumbPrint);
            } catch (Exception ex) {
                ex.printStackTrace();
                LOGGER.error("getBiometricData :: encrypt :: ", ex);
            }
        }

        biometricData.setRequestedScore(qualityRequestScore + "");
        biometricData.setQualityScore(qualityScore + "");
        biometricData.setTransactionId(transactionId);

        ObjectMapper mapper = new ObjectMapper ();
        mapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);

        String currentBioData = mapper.writeValueAsString(biometricData);

        String dataBlockSignBase64 = deviceHelper.signBiometricsData(currentBioData);
        biometric.setData (dataBlockSignBase64);

        byte[] previousBioDataHash = null;
        if (previousHash == null || previousHash.trim().length() == 0) {
            byte [] previousDataByteArr = StringHelper.toUtf8ByteArray ("");
            previousBioDataHash = generateHash(previousDataByteArr);
        } else {
            previousBioDataHash = decodeHex(previousHash);
        }

        byte [] currentDataByteArr = StringHelper.base64UrlDecode(bioValue);
        byte[] currentBioDataHash = generateHash (currentDataByteArr);
        byte[] finalBioDataHash = new byte[currentBioDataHash.length + previousBioDataHash.length];
        System.arraycopy (previousBioDataHash, 0, finalBioDataHash, 0, previousBioDataHash.length);
        System.arraycopy (currentBioDataHash, 0, finalBioDataHash, previousBioDataHash.length, currentBioDataHash.length);

        biometric.setHash(toHex (generateHash (finalBioDataHash)));

        return biometric;
    }

    private DeviceInfo getDeviceInfo(String bioType) throws IOException {
        var deviceInfo = new DeviceInfo();

        String serialNo = "";
        String make = "";
        String model = "";
        String type = "";
        String deviceSubType = "";
        String deviceProvider = "";
        String deviceProviderId = "";
        String digitalId = "";

        switch (bioType) {
            case SBIConstant.MOSIP_BIOMETRIC_TYPE_FINGER:
                serialNo = env.getProperty("ida.device.finger.serialNo");
                make = env.getProperty("ida.device.finger.make");
                model = env.getProperty("ida.device.finger.model");
                type = env.getProperty("ida.device.finger.type");
                deviceSubType = env.getProperty("ida.device.finger.deviceSubType");
                deviceProvider = env.getProperty("ida.device.finger.deviceProvider");
                deviceProviderId = env.getProperty("ida.device.finger.deviceProviderId");

                deviceInfo.setDeviceCode(serialNo);
                digitalId = GenerateDigitalId(serialNo,make,model,type,deviceSubType,deviceProvider,deviceProviderId);
                break;
            case SBIConstant.MOSIP_BIOMETRIC_TYPE_FACE:
                serialNo = env.getProperty("ida.device.face.serialNo");
                make = env.getProperty("ida.device.face.make");
                model = env.getProperty("ida.device.face.model");
                type = env.getProperty("ida.device.face.type");
                deviceSubType = env.getProperty("ida.device.face.deviceSubType");
                deviceProvider = env.getProperty("ida.device.face.deviceProvider");
                deviceProviderId = env.getProperty("ida.device.face.deviceProviderId");

                deviceInfo.setDeviceCode(serialNo);
                digitalId = GenerateDigitalId(serialNo,make,model,type,deviceSubType,deviceProvider,deviceProviderId);
                break;
            case SBIConstant.MOSIP_BIOMETRIC_TYPE_IRIS:
                serialNo = env.getProperty("ida.device.iris.serialNo");
                make = env.getProperty("ida.device.iris.make");
                model = env.getProperty("ida.device.iris.model");
                type = env.getProperty("ida.device.iris.type");
                deviceSubType = env.getProperty("ida.device.iris.deviceSubType");
                deviceProvider = env.getProperty("ida.device.iris.deviceProvider");
                deviceProviderId = env.getProperty("ida.device.iris.deviceProviderId");

                deviceInfo.setDeviceCode(serialNo);
                digitalId = GenerateDigitalId(serialNo,make,model,type,deviceSubType,deviceProvider,deviceProviderId);
                break;
            default:
                digitalId = "";
                break;
        }

        var signedDigitalId = deviceHelper.signDigitalId(digitalId);
        deviceInfo.setDigitalId(signedDigitalId);
        deviceInfo.setServiceVersion(env.getProperty("ida.device.service.version"));

        return deviceInfo;
    }

    private String GenerateDigitalId(String serialNo, String make, String model, String type , String deviceSubType, String deviceProvider, String deviceProviderId) {
        JSONObject json = new JSONObject();
        json.put("serialNo", serialNo);
        json.put("make", make);
        json.put("model", model);
        json.put("type", type);
        json.put("deviceSubType", deviceSubType);
        json.put("deviceProvider", deviceProvider);
        json.put("deviceProviderId", deviceProviderId);
        json.put("dateTime", CryptoUtility.getTimestamp());
        return json.toJSONString();
    }

    private String toHex(byte[] bytes) {
        return Hex.encodeHexString(bytes).toUpperCase();
    }

    private byte[] generateHash(final byte[] bytes) throws NoSuchAlgorithmException{
        String HASH_ALGORITHM_NAME = "SHA-256";
        MessageDigest messageDigest = MessageDigest.getInstance(HASH_ALGORITHM_NAME);
        return messageDigest.digest(bytes);
    }

    private byte[] decodeHex(String hexData) throws DecoderException{
        return Hex.decodeHex(hexData);
    }
}