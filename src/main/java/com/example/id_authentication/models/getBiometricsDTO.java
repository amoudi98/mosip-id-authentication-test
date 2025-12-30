package com.example.id_authentication.models;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class getBiometricsDTO {
    private String bioType;
    private String bioSubType;
    private String bioValue;
    private Integer qualityScore;
    private Integer qualityRequestScore;
    private String env;
    private String purpose;
    private String specVersion;
    private int timeout;
    private String domainUri;
    private String individualId;
    private String individualIdType;
}