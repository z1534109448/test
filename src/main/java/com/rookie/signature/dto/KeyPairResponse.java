package com.rookie.signature.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class KeyPairResponse {
    private String publicKey;
    private String privateKey;
}
