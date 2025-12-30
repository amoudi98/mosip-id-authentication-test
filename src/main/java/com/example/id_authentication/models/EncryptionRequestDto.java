package com.example.id_authentication.models;

import lombok.Data;

import java.util.Map;

@Data
public class EncryptionRequestDto {
    private Map<String, Object> identityRequest;
}
