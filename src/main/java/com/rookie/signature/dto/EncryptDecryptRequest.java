package com.rookie.signature.dto;

import lombok.Data;

@Data
public class EncryptDecryptRequest {
    private String key;
    private String data;
}
