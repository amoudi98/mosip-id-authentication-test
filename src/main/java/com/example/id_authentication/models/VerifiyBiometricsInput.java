package com.example.id_authentication.models;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
public class VerifiyBiometricsInput {
    private String bioType;
    private String bioSubType;
    private String bioValue;
    private String individualId;
    private String individualIdType;
}