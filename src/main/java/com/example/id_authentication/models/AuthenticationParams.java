package com.example.id_authentication.models;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

import java.util.ArrayList;

@Data
@Builder
@AllArgsConstructor
public class AuthenticationParams {
    private String individualId;
    private String individualIdType;
    private ArrayList<BiometricData> biometricData;
    private Boolean consent;
    private String authType;
    private String transactionId;
}