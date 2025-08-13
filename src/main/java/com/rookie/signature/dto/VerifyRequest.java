package com.rookie.signature.dto;

import lombok.Data;

@Data
public class VerifyRequest {
    private String publicKey;
    private String data;
    private String sign;
}
