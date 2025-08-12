package com.rookie.signature;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;


class SignatureApplicationTests {

    @Test
    void testRsaEncryptionDecryption() {
        // 1. Generate key pair
        Map<String, Object> keyMap = RsaUtil.generateKey();
        String publicKey = RsaUtil.getPublicKey(keyMap);
        String privateKey = RsaUtil.getPrivateKey(keyMap);

        assertNotNull(publicKey);
        assertNotNull(privateKey);

        // 2. Test data
        String originalData = "test data for encryption";

        // 3. Encrypt with public key, decrypt with private key
        String encryptedData = RsaUtil.encryptByPublicKey(publicKey, originalData);
        String decryptedData = RsaUtil.decryptByPrivateKey(privateKey, encryptedData);
        assertEquals(originalData, decryptedData);
    }

    @Test
    void testRsaSigningVerification() {
        // 1. Generate key pair
        Map<String, Object> keyMap = RsaUtil.generateKey();
        String publicKey = RsaUtil.getPublicKey(keyMap);
        String privateKey = RsaUtil.getPrivateKey(keyMap);

        assertNotNull(publicKey);
        assertNotNull(privateKey);

        // 2. Test data
        String originalData = "test data for signing";

        // 3. Sign with private key, verify with public key
        String sign = RsaUtil.sign(privateKey, originalData);
        boolean isVerified = RsaUtil.verify(publicKey, originalData, sign);
        assertTrue(isVerified);
    }

    @Test
    void testRsaPrivateEncryptionPublicDecryption() {
        // 1. Generate key pair
        Map<String, Object> keyMap = RsaUtil.generateKey();
        String publicKey = RsaUtil.getPublicKey(keyMap);
        String privateKey = RsaUtil.getPrivateKey(keyMap);

        assertNotNull(publicKey);
        assertNotNull(privateKey);

        // 2. Test data
        String originalData = "test data for private encryption";

        // 3. Encrypt with private key, decrypt with public key
        String encryptedData = RsaUtil.encryptByPrivateKey(privateKey, originalData);
        String decryptedData = RsaUtil.decryptByPublicKey(publicKey, encryptedData);
        assertEquals(originalData, decryptedData);
    }
}
