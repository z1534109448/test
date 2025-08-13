package com.rookie.signature.service;

import com.rookie.signature.RsaUtil;
import com.rookie.signature.dto.KeyPairResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class CryptoServiceImpl implements CryptoService {

    private final RsaUtil rsaUtil;

    @Autowired
    public CryptoServiceImpl(RsaUtil rsaUtil) {
        this.rsaUtil = rsaUtil;
    }

    @Override
    public KeyPairResponse generateKeys() {
        Map<String, Object> keyMap = rsaUtil.generateKey();
        String publicKey = rsaUtil.getPublicKey(keyMap);
        String privateKey = rsaUtil.getPrivateKey(keyMap);
        return new KeyPairResponse(publicKey, privateKey);
    }

    @Override
    public String encrypt(String publicKey, String data) {
        return rsaUtil.encryptByPublicKey(publicKey, data);
    }

    @Override
    public String decrypt(String privateKey, String data) {
        return rsaUtil.decryptByPrivateKey(privateKey, data);
    }

    @Override
    public String sign(String privateKey, String data) {
        return rsaUtil.sign(privateKey, data);
    }

    @Override
    public boolean verify(String publicKey, String data, String sign) {
        return rsaUtil.verify(publicKey, data, sign);
    }
}
