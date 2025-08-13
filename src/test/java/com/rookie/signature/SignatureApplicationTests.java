package com.rookie.signature;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SignatureApplicationTests {

    private final RsaUtil rsaUtil = new RsaUtil();

    @Test
    void testRsaEncryptionDecryption() {
        // 1. Generate key pair
        Map<String, Object> keyMap = rsaUtil.generateKey();
        String publicKey = rsaUtil.getPublicKey(keyMap);
        String privateKey = rsaUtil.getPrivateKey(keyMap);

        assertNotNull(publicKey);
        assertNotNull(privateKey);

        // 2. Test data
        String originalData = "test data for encryption";

        // 3. Encrypt with public key, decrypt with private key
        String encryptedData = rsaUtil.encryptByPublicKey(publicKey, originalData);
        String decryptedData = rsaUtil.decryptByPrivateKey(privateKey, encryptedData);
        assertEquals(originalData, decryptedData);
    }

    @Test
    void testRsaSigningVerification() {
        // 1. Generate key pair
        Map<String, Object> keyMap = rsaUtil.generateKey();
        String publicKey = rsaUtil.getPublicKey(keyMap);
        String privateKey = rsaUtil.getPrivateKey(keyMap);

        assertNotNull(publicKey);
        assertNotNull(privateKey);

        // 2. Test data
        String originalData = "test data for signing";

        // 3. Sign with private key, verify with public key
        String sign = rsaUtil.sign(privateKey, originalData);
        boolean isVerified = rsaUtil.verify(publicKey, originalData, sign);
        assertTrue(isVerified);
    }

    @Test
    void testRsaPrivateEncryptionPublicDecryption() {
        // 1. Generate key pair
        Map<String, Object> keyMap = rsaUtil.generateKey();
        String publicKey = rsaUtil.getPublicKey(keyMap);
        String privateKey = rsaUtil.getPrivateKey(keyMap);

        assertNotNull(publicKey);
        assertNotNull(privateKey);

        // 2. Test data
        String originalData = "test data for private encryption";

        // 3. Encrypt with private key, decrypt with public key
        String encryptedData = rsaUtil.encryptByPrivateKey(privateKey, originalData);
        String decryptedData = rsaUtil.decryptByPublicKey(publicKey, encryptedData);
        assertEquals(originalData, decryptedData);
    }
}
