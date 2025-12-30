package com.example.id_authentication.utils;

import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import org.apache.commons.codec.digest.DigestUtils;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.lang.JoseException;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Service;

@Service
public class JwtUtility {
    private static final String signAlgorithm="RS256";

    private final Environment env;
    private final FileUtils fileUtils;

    public JwtUtility(Environment env, FileUtils fileUtils){
        this.env = env;
        this.fileUtils = fileUtils;
    }

    public String getJwt(byte[] data, PrivateKey privateKey, X509Certificate x509Certificate) {
        String jwsToken = null;
        JsonWebSignature jws = new JsonWebSignature();

        if(x509Certificate != null) {
            List<X509Certificate> certList = new ArrayList<>();
            certList.add(x509Certificate);
            X509Certificate[] certArray = certList.toArray(new X509Certificate[] {});
            jws.setCertificateChainHeaderValue(certArray);
        }

        jws.setPayloadBytes(data);
        jws.setAlgorithmHeaderValue(signAlgorithm);
        jws.setHeader(org.jose4j.jwx.HeaderParameterNames.TYPE, "JWT");
        jws.setKey(privateKey);
        jws.setDoKeyValidation(false);
        try {
            jwsToken = jws.getCompactSerialization();
        } catch (JoseException e) {
            e.printStackTrace();
        }

        return jwsToken;
    }

    public X509Certificate getCertificateToEncryptCaptureBioValue() throws Exception {
        String certificate = getCertificateFromIDA();
        certificate = trimBeginEnd(certificate);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate x509Certificate = (X509Certificate) cf.generateCertificate(
                new ByteArrayInputStream(Base64.getDecoder().decode(certificate)));
        return x509Certificate;
    }

    public byte[] getCertificateThumbprint(Certificate cert) throws CertificateEncodingException {
        return DigestUtils.sha256(cert.getEncoded());
    }

    private String getCertificateFromIDA() throws Exception {
        String pem = Files.readString(Paths.get(fileUtils.getFilePath(env.getProperty("mosip.ida.fir.cert.path"))));
        return pem;
    }

    private static String trimBeginEnd(String pKey) {
        pKey = pKey.replaceAll("-*BEGIN([^-]*)-*(\r?\n)?", "");
        pKey = pKey.replaceAll("-*END([^-]*)-*(\r?\n)?", "");
        pKey = pKey.replaceAll("\\s", "");
        return pKey;
    }
}