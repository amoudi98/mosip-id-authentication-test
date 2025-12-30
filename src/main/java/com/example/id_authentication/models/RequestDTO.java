package com.example.id_authentication.models;

import lombok.Data;

import java.util.List;

@Data
public class RequestDTO {
    /** variable to hold otp value */
    private String otp;

    /** variable to hold timestamp value */
    private String timestamp;

    /** variable to hold identity value */
    private IdentityDTO demographics;

    /** List of biometric identity info */
    private List<BioIdentityInfoDTO> biometrics;
}
