package com.example.id_authentication.models;

import lombok.Data;

@Data
public class AuthTypeDTO {
    /** For demo Authentication */
    private boolean demo;

    /** For biometric Authentication */
    private boolean bio;

    /** For otp Authentication */
    private boolean otp;

    /** For pin Authentication */
    private boolean pin;

}
