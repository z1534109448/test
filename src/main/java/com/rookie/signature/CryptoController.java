package com.rookie.signature;

import com.rookie.signature.dto.DataResponse;
import com.rookie.signature.dto.EncryptDecryptRequest;
import com.rookie.signature.dto.KeyPairResponse;
import com.rookie.signature.dto.SignRequest;
import com.rookie.signature.dto.VerifyRequest;
import com.rookie.signature.dto.VerifyResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/crypto")
public class CryptoController {

    @GetMapping("/generate-keys")
    public KeyPairResponse generateKeys() {
        Map<String, Object> keyMap = RsaUtil.generateKey();
        String publicKey = RsaUtil.getPublicKey(keyMap);
        String privateKey = RsaUtil.getPrivateKey(keyMap);
        return new KeyPairResponse(publicKey, privateKey);
    }

    @PostMapping("/encrypt")
    public DataResponse encrypt(@RequestBody EncryptDecryptRequest request) {
        String encryptedData = RsaUtil.encryptByPublicKey(request.getKey(), request.getData());
        return new DataResponse(encryptedData);
    }

    @PostMapping("/decrypt")
    public DataResponse decrypt(@RequestBody EncryptDecryptRequest request) {
        String decryptedData = RsaUtil.decryptByPrivateKey(request.getKey(), request.getData());
        return new DataResponse(decryptedData);
    }

    @PostMapping("/sign")
    public DataResponse sign(@RequestBody SignRequest request) {
        String sign = RsaUtil.sign(request.getPrivateKey(), request.getData());
        return new DataResponse(sign);
    }

    @PostMapping("/verify")
    public VerifyResponse verify(@RequestBody VerifyRequest request) {
        boolean isVerified = RsaUtil.verify(request.getPublicKey(), request.getData(), request.getSign());
        return new VerifyResponse(isVerified);
    }
}
