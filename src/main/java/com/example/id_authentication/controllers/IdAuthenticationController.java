package com.example.id_authentication.controllers;

import com.example.id_authentication.models.*;
import com.example.id_authentication.services.VerificationService;
import org.apache.commons.codec.DecoderException;
import org.jose4j.lang.JoseException;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

@RestController
@RequestMapping("id-authentication")
public class IdAuthenticationController {
    private final VerificationService verificationService;

    public IdAuthenticationController(VerificationService verificationService) {
        this.verificationService = verificationService;
    }

    @PostMapping("/verifiy-finger")
    public ResponseEntity<?> verifiyFingerPrint(@RequestBody VerifiyBiometricsInput input) throws DecoderException, IOException, NoSuchAlgorithmException, JoseException, UnrecoverableEntryException, CertificateException, KeyStoreException, KeyManagementException {
        return ResponseEntity.ok(verificationService.verifiyFingerPrint(input));
    }

    @PostMapping("/verifiy-face")
    public ResponseEntity<?> verifiyFace(@RequestBody VerifiyBiometricsInput input) throws DecoderException, JoseException, UnrecoverableEntryException, CertificateException, IOException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        return ResponseEntity.ok(verificationService.verifiyFace(input));
    }

    @PostMapping("/verifiy-iris")
    public ResponseEntity<?> verifiyIris(@RequestBody VerifiyIrisInput input) throws DecoderException, JoseException, UnrecoverableEntryException, CertificateException, IOException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        return ResponseEntity.ok(verificationService.verifiyIris(input));
    }
}