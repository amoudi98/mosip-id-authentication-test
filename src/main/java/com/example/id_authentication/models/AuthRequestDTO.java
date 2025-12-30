package com.example.id_authentication.models;

import lombok.Data;

@Data
public class AuthRequestDTO {
    private String id;

    private String version;

    private String transactionID;

    private String requestTime;

    private RequestDTO request;

    private boolean consentObtained;

    private String individualId;

    private String requestHMAC;

    private String thumbprint;

    private String requestSessionKey;

    private String env;

    private String  domainUri;

    @Deprecated(since="1.2.0")
    private AuthTypeDTO requestedAuth;

    @Deprecated(since="1.2.0")
    private String individualIdType;
}
