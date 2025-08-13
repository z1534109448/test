package com.rookie.signature;

import com.rookie.signature.dto.KeyPairResponse;
import com.rookie.signature.service.CryptoService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class SignatureApplication implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(SignatureApplication.class);

    private final CryptoService cryptoService;

    @Autowired
    public SignatureApplication(CryptoService cryptoService) {
        this.cryptoService = cryptoService;
    }

    public static void main(String[] args) {
        SpringApplication.run(SignatureApplication.class, args);
    }

    @Override
    public void run(String... args) throws Exception {
        log.info("开始执行RSA加解密和签名验签功能演示 (已重构为Service层)...");

        // 1. 生成密钥对
        KeyPairResponse keyPair = cryptoService.generateKeys();
        String publicKey = keyPair.getPublicKey();
        String privateKey = keyPair.getPrivateKey();
        log.info("生成公钥: {}", publicKey);
        log.info("生成私钥: {}", privateKey);

        // 2. 准备测试数据
        String originalData = "这是一段用于测试RSA功能的明文";
        log.info("原始数据: {}", originalData);

        // 3. 演示公钥加密、私钥解密
        log.info("--- 开始演示公钥加密、私钥解密 ---");
        String encryptedData = cryptoService.encrypt(publicKey, originalData);
        log.info("公钥加密后的数据: {}", encryptedData);

        String decryptedData = cryptoService.decrypt(privateKey, encryptedData);
        log.info("私钥解密后的数据: {}", decryptedData);

        if (originalData.equals(decryptedData)) {
            log.info("公钥加密、私钥解密 -> 成功: 解密后的数据与原始数据一致");
        } else {
            log.error("公钥加密、私钥解密 -> 失败: 解密后的数据与原始数据不一致");
        }

        // 4. 演示私钥签名、公钥验签
        log.info("--- 开始演示私钥签名、公钥验签 ---");
        String sign = cryptoService.sign(privateKey, originalData);
        log.info("私钥签名后的数据: {}", sign);

        boolean verify = cryptoService.verify(publicKey, originalData, sign);
        log.info("公钥验签结果: {}", verify);

        if (verify) {
            log.info("私钥签名、公钥验签 -> 成功: 验证通过");
        } else {
            log.error("私钥签名、公钥验签 -> 失败: 验证不通过");
        }
    }
}
