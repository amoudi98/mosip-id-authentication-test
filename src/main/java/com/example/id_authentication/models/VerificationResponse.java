package com.example.id_authentication.models;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class VerificationResponse {
    private String transactionID;
    private String version;
    private String id;
    private List<VerificationResponseError> errors;
    private String responseTime;
    private Response response;
}