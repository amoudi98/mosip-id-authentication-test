package com.example.id_authentication.models;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class IdentityInfoDTO {
    /** Variable to hold language */
    private String language;

    /** Variable to hold value */
    private String value;
}
