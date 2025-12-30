package com.example.id_authentication.models;

import lombok.Data;

@Data
public class EncryptionResponseDto {
    String encryptedSessionKey;
    String encryptedIdentity;
    String requestHMAC;
    String thumbprint;
}
