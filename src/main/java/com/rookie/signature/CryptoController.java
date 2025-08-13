package com.rookie.signature;

import com.rookie.signature.dto.DataResponse;
import com.rookie.signature.dto.EncryptDecryptRequest;
import com.rookie.signature.dto.KeyPairResponse;
import com.rookie.signature.dto.SignRequest;
import com.rookie.signature.dto.VerifyRequest;
import com.rookie.signature.dto.VerifyResponse;
import com.rookie.signature.service.CryptoService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/crypto")
public class CryptoController {

    private final CryptoService cryptoService;

    @Autowired
    public CryptoController(CryptoService cryptoService) {
        this.cryptoService = cryptoService;
    }

    @GetMapping("/generate-keys")
    public KeyPairResponse generateKeys() {
        return cryptoService.generateKeys();
    }

    @PostMapping("/encrypt")
    public DataResponse encrypt(@RequestBody EncryptDecryptRequest request) {
        String encryptedData = cryptoService.encrypt(request.getKey(), request.getData());
        return new DataResponse(encryptedData);
    }

    @PostMapping("/decrypt")
    public DataResponse decrypt(@RequestBody EncryptDecryptRequest request) {
        String decryptedData = cryptoService.decrypt(request.getKey(), request.getData());
        return new DataResponse(decryptedData);
    }

    @PostMapping("/sign")
    public DataResponse sign(@RequestBody SignRequest request) {
        String sign = cryptoService.sign(request.getPrivateKey(), request.getData());
        return new DataResponse(sign);
    }

    @PostMapping("/verify")
    public VerifyResponse verify(@RequestBody VerifyRequest request) {
        boolean isVerified = cryptoService.verify(request.getPublicKey(), request.getData(), request.getSign());
        return new VerifyResponse(isVerified);
    }
}
