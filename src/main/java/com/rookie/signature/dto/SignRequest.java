package com.rookie.signature.dto;

import lombok.Data;

@Data
public class SignRequest {
    private String privateKey;
    private String data;
}
