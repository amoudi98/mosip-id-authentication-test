package com.example.id_authentication.models;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
@AllArgsConstructor
public class BiometricData {
    private String data;
    private String hash;
    private String sessionKey;
    private String thumbprint;
}
