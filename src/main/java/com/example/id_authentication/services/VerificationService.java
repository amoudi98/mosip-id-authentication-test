package com.example.id_authentication.services;

import com.example.id_authentication.constants.SBIConstant;
import com.example.id_authentication.models.*;
import com.example.id_authentication.models.Error;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.codec.DecoderException;
import org.jose4j.lang.JoseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.Environment;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;

@Service
public class VerificationService {
    private static final Logger LOGGER = LoggerFactory.getLogger(VerificationService.class);
    private final SecureRandom secureRandom = new SecureRandom();
    private final AuthenticationService authenticationService;
    private final SBIService sbiService;
    private final Environment env;
    private final RestTemplate restTemplate;

    public VerificationService(AuthenticationService authenticationService, SBIService sbiService, Environment env, RestTemplate restTemplate){
        this.authenticationService = authenticationService;
        this.sbiService = sbiService;
        this.env = env;
        this.restTemplate = restTemplate;
    }

    public Result<VerificationResponse> verifiyFingerPrint(VerifiyBiometricsInput input) throws DecoderException, IOException, NoSuchAlgorithmException, JoseException, UnrecoverableEntryException, CertificateException, KeyStoreException, KeyManagementException {
        LOGGER.info("Finger print verification started....");
        var captureRequestDto = prepareCaptureRequest();
        var transactionId = generateTransactionId();

        int qualityScore = env.getProperty("qualityScore", Integer.class, 85);
        int qualityRequestScore = env.getProperty("qualityRequestScore", Integer.class, 70);

        LOGGER.info("Extracting Biometric Data....");
        BioMetricsDto biometricsResult = sbiService.getBiometricData(
                transactionId,
                captureRequestDto,
                "",
                SBIConstant.MOSIP_BIOMETRIC_TYPE_FINGER,
                input.getBioSubType(),
                input.getBioValue(),
                qualityScore,
                qualityRequestScore,
                true
        );

        var bioData = BiometricData.builder()
                .data(biometricsResult.getData())
                .hash(biometricsResult.getHash())
                .sessionKey(biometricsResult.getSessionKey())
                .thumbprint(biometricsResult.getThumbprint())
                .build();

        var authenticationParams = AuthenticationParams.builder()
                .authType("bio")
                .individualId(input.getIndividualId())
                .individualIdType(input.getIndividualIdType())
                .transactionId(transactionId)
                .consent(true)
                .biometricData(new ArrayList<>(List.of(bioData)))
                .build();

        LOGGER.info("Preparing Authentication Data....");
        var authenticationDataResult = authenticationService.prepareAuthenticationData(authenticationParams);

//        var dataToSign = "Hello Ahmed";
//
//        var signedData = authenticationService.sign(dataToSign,
//                false,
//                true,
//                false,
//                null,
//                "",
//                "");
//
//        var isValid = authenticationService.verifyDetachedJws(signedData,dataToSign);

        return sendVerificationRequest(
                authenticationDataResult.getAuthSignature(),
                authenticationDataResult.getAuthData());
    }

    public Result<VerificationResponse> verifiyFace(VerifiyBiometricsInput input) throws DecoderException, IOException, NoSuchAlgorithmException, JoseException, UnrecoverableEntryException, CertificateException, KeyStoreException, KeyManagementException {
        LOGGER.info("Face verification started....");
        var captureRequestDto = prepareCaptureRequest();
        var transactionId = generateTransactionId();

        int qualityScore = env.getProperty("qualityScore", Integer.class, 85);
        int qualityRequestScore = env.getProperty("qualityRequestScore", Integer.class, 70);

        BioMetricsDto biometricsResult = sbiService.getBiometricData(
                transactionId,
                captureRequestDto,
                "",
                SBIConstant.MOSIP_BIOMETRIC_TYPE_FACE,
                "",
                input.getBioValue(),
                qualityScore,
                qualityRequestScore,
                true
        );

        var bioData = BiometricData.builder()
                .data(biometricsResult.getData())
                .hash(biometricsResult.getHash())
                .sessionKey(biometricsResult.getSessionKey())
                .thumbprint(biometricsResult.getThumbprint())
                .build();

        var authenticationParams = AuthenticationParams.builder()
                .authType("bio")
                .individualId(input.getIndividualId())
                .individualIdType(input.getIndividualIdType())
                .transactionId(transactionId)
                .consent(true)
                .biometricData(new ArrayList<>(List.of(bioData)))
                .build();

        var authenticationDataResult = authenticationService.prepareAuthenticationData(authenticationParams);

        return sendVerificationRequest(
                authenticationDataResult.getAuthSignature(),
                authenticationDataResult.getAuthData()
        );
    }

    public Result<VerificationResponse> verifiyIris(VerifiyIrisInput input) throws DecoderException, IOException, NoSuchAlgorithmException, JoseException, UnrecoverableEntryException, CertificateException, KeyStoreException, KeyManagementException {
        LOGGER.info("Iris verification started....");
        var captureRequestDto = prepareCaptureRequest();
        var transactionId = generateTransactionId();

        int qualityScore = env.getProperty("qualityScore", Integer.class, 85);
        int qualityRequestScore = env.getProperty("qualityRequestScore", Integer.class, 70);

        List<BioMetricsDto> biometrics = new ArrayList<BioMetricsDto> ();
        List<Biometric> biometricData = input.getBiometrics();
        if (biometricData != null && !biometricData.isEmpty())
        {
            int bioCounter = 0;
            int bioCount = biometricData.size();
            String previousHash = "";

            for (Biometric pair: biometricData) {
                if (bioCounter > bioCount)
                    break;

                if ((bioCounter < bioCount)) {
                    String bioData = pair.getValue();
                    if (bioData != null && !bioData.isEmpty()) {
                        BioMetricsDto bioDto = sbiService.getBiometricData(
                                transactionId,
                                captureRequestDto,
                                previousHash,
                                SBIConstant.MOSIP_BIOMETRIC_TYPE_IRIS,
                                pair.getSubType(),
                                bioData,
                                qualityScore,
                                qualityRequestScore,
                                true);
                        if (bioDto != null) {
                            biometrics.add(bioDto);
                            previousHash = bioDto.getHash();
                        }
                    }

                    bioCounter++;
                }
            }
        }

        var bioData = new ArrayList<BiometricData>();
        for (BioMetricsDto bio : biometrics) {
            bioData.add(BiometricData.builder()
                    .data(bio.getData())
                    .hash(bio.getHash())
                    .sessionKey(bio.getSessionKey())
                    .thumbprint(bio.getThumbprint())
                    .build());
        }

        var authenticationParams = AuthenticationParams.builder()
                .authType("bio")
                .individualId(input.getIndividualId())
                .individualIdType(input.getIndividualIdType())
                .transactionId(transactionId)
                .consent(true)
                .biometricData(bioData)
                .build();

        var authenticationDataResult = authenticationService.prepareAuthenticationData(authenticationParams);

        return sendVerificationRequest(
                authenticationDataResult.getAuthSignature(),
                authenticationDataResult.getAuthData()
        );
    }

    private Result<VerificationResponse> sendVerificationRequest(String signature,String requestJson) throws JsonProcessingException {
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add("signature", signature);
        httpHeaders.add("Content-type", MediaType.APPLICATION_JSON_VALUE);
        httpHeaders.add("Authorization", "Authorization");
        HttpEntity<String> httpEntity = new HttpEntity<>(requestJson, httpHeaders);

        String url = env.getProperty("ida.auth.url");
        LOGGER.info("Auth URL: {}", url);
        //LOGGER.info("Auth Request : \n{}", requestJson);

        Result<VerificationResponse> verificationResponse = null;
        try {
            var response = restTemplate.exchange(url, HttpMethod.POST, httpEntity, VerificationResponse.class);

            if (response.getBody() != null && response.getStatusCode().is2xxSuccessful()) {
                var resBody = response.getBody();
                if (resBody.getErrors() == null){
                    LOGGER.info("Auth Response : \n{}", new ObjectMapper().writeValueAsString(resBody));
                    LOGGER.info("MOSIP Verification Done ...");
                    verificationResponse = Result.success(resBody);
                }else{
                    var errors = new ArrayList<Error>();

                    for (var error : resBody.getErrors()){
                        errors.add(Error.builder()
                                        .code(error.getErrorCode())
                                        .category(ErrorCategory.BadRequest)
                                        .message(error.getErrorMessage())
                                        .build());
                    }
                    verificationResponse = Result.failure(errors);
                }

            }

        } catch (Exception e) {
            var errors = new ArrayList<Error>();
            errors.add(Error.builder()
                    .code("EXCEPTION")
                    .category(ErrorCategory.ServerError)
                    .message(e.getMessage())
                    .build());

            verificationResponse = Result.failure(errors);
            LOGGER.error("Authentication Failed with Error : {}", e.getMessage());
        }

        return verificationResponse;
    }

    private String generateTransactionId() {
        long min = 1_000_000_000L;
        long max = 9_999_999_999L;
        long number = min + (Math.abs(secureRandom.nextLong()) % (max - min + 1));
        return Long.toString(number);
    }

    private CaptureRequestDto prepareCaptureRequest(){
        return CaptureRequestDto.builder()
                .env(env.getProperty("env"))
                .purpose(env.getProperty("purpose"))
                .specVersion(env.getProperty("specVersion"))
                .domainUri(env.getProperty("domainUri"))
                .build();
    }
}