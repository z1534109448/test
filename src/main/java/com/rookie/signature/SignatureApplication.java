package com.rookie.signature;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.util.Map;

@SpringBootApplication
public class SignatureApplication implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(SignatureApplication.class);

    public static void main(String[] args) {
        SpringApplication.run(SignatureApplication.class, args);
    }

    @Override
    public void run(String... args) throws Exception {
        log.info("开始执行RSA加解密和签名验签功能演示...");

        // 1. 生成密钥对
        Map<String, Object> keyMap = RsaUtil.generateKey();
        String publicKey = RsaUtil.getPublicKey(keyMap);
        String privateKey = RsaUtil.getPrivateKey(keyMap);
        log.info("生成公钥: {}", publicKey);
        log.info("生成私钥: {}", privateKey);

        // 2. 准备测试数据
        String originalData = "这是一段用于测试RSA功能的明文";
        log.info("原始数据: {}", originalData);

        // 3. 演示公钥加密、私钥解密
        log.info("--- 开始演示公钥加密、私钥解密 ---");
        String encryptedData = RsaUtil.encryptByPublicKey(publicKey, originalData);
        log.info("公钥加密后的数据: {}", encryptedData);

        String decryptedData = RsaUtil.decryptByPrivateKey(privateKey, encryptedData);
        log.info("私钥解密后的数据: {}", decryptedData);

        if (originalData.equals(decryptedData)) {
            log.info("公钥加密、私钥解密 -> 成功: 解密后的数据与原始数据一致");
        } else {
            log.error("公钥加密、私钥解密 -> 失败: 解密后的数据与原始数据不一致");
        }

        // 4. 演示私钥签名、公钥验签
        log.info("--- 开始演示私钥签名、公钥验签 ---");
        String sign = RsaUtil.sign(privateKey, originalData);
        log.info("私钥签名后的数据: {}", sign);

        boolean verify = RsaUtil.verify(publicKey, originalData, sign);
        log.info("公钥验签结果: {}", verify);

        if (verify) {
            log.info("私钥签名、公钥验签 -> 成功: 验证通过");
        } else {
            log.error("私钥签名、公钥验签 -> 失败: 验证不通过");
        }

        log.info("--- 演示私钥加密、公钥解密 ---");
        String encryptedDataByPrivateKey = RsaUtil.encryptByPrivateKey(privateKey, originalData);
        log.info("私钥加密后的数据: {}", encryptedDataByPrivateKey);
        String decryptedDataByPublicKey = RsaUtil.decryptByPublicKey(publicKey, encryptedDataByPrivateKey);
        log.info("公钥解密后的数据: {}", decryptedDataByPublicKey);
        if (originalData.equals(decryptedDataByPublicKey)) {
            log.info("私钥加密、公钥解密 -> 成功: 解密后的数据与原始数据一致");
        } else {
            log.error("私钥加密、公钥解密 -> 失败: 解密后的数据与原始数据不一致");
        }
    }
}
