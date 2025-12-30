package com.example.id_authentication.models;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.util.HashMap;
import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class VerifiyIrisInput {
    private String bioType;
    private List<Biometric> biometrics;
    private String individualId;
    private String individualIdType;
}