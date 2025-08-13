package com.rookie.signature.service;

import com.rookie.signature.dto.KeyPairResponse;
import java.util.Map;

public interface CryptoService {
    KeyPairResponse generateKeys();
    String encrypt(String publicKey, String data);
    String decrypt(String privateKey, String data);
    String sign(String privateKey, String data);
    boolean verify(String publicKey, String data, String sign);
}
