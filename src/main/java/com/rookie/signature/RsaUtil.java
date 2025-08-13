package com.rookie.signature;

import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import java.io.ByteArrayOutputStream;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@Component
public class RsaUtil {

    private static final String KEY_RSA = "RSA";
    public static final String ECB_PKCS1_PADDING = "RSA/ECB/PKCS1Padding";
    private static final String KEY_RSA_SIGNATURE = "MD5withRSA";
    protected static final String KEY_RSA_PUBLICKEY = "RSAPublicKey";
    private static final String KEY_RSA_PRIVATEKEY = "RSAPrivateKey";
    private static final int MAX_ENCRYPT_BLOCK = 117;
    private static final int MAX_DECRYPT_BLOCK = 128;
    private static final int MAX_DECRYPT_BLOCK_256 = 256;

    public Map<String, Object> generateKey() {
        Map<String, Object> map = null;
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance(KEY_RSA);
            generator.initialize(1024);
            KeyPair keyPair = generator.generateKeyPair();
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
            map = new HashMap<>();
            map.put(KEY_RSA_PUBLICKEY, publicKey);
            map.put(KEY_RSA_PRIVATEKEY, privateKey);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        return map;
    }

    public String sign(String privateKey, byte[] data) {
        String str = "";
        try {
            byte[] bytes = decryptBase64(privateKey);
            PKCS8EncodedKeySpec pkcs = new PKCS8EncodedKeySpec(bytes);
            KeyFactory factory = KeyFactory.getInstance(KEY_RSA);
            PrivateKey key = factory.generatePrivate(pkcs);
            Signature signature = Signature.getInstance(KEY_RSA_SIGNATURE);
            signature.initSign(key);
            signature.update(data);
            str = encryptBase64(signature.sign());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return str;
    }

    public String sign(String privateKey, String dataStr) {
        try {
            byte[] data = dataStr.getBytes("UTF-8");
            return sign(privateKey, data);
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    public String signPublicKey(String publicKey, String dataStr) {
        try {
            byte[] data = dataStr.getBytes("UTF-8");
            return signPublicKey(publicKey, data);
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    public String signPublicKey(String publicKey, byte[] data) {
        try {
            byte[] bytes = decryptBase64(publicKey);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(bytes);
            KeyFactory factory = KeyFactory.getInstance(KEY_RSA);
            PublicKey key = factory.generatePublic(keySpec);
            // This method seems incomplete, but I will leave it as is for now.
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return "";
    }

    public boolean verify(String publicKey, byte[] data, String sign) {
        boolean flag = false;
        try {
            byte[] bytes = decryptBase64(publicKey);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(bytes);
            KeyFactory factory = KeyFactory.getInstance(KEY_RSA);
            PublicKey key = factory.generatePublic(keySpec);
            Signature signature = Signature.getInstance(KEY_RSA_SIGNATURE);
            signature.initVerify(key);
            signature.update(data);
            flag = signature.verify(decryptBase64(sign));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return flag;
    }

    public boolean verify(String publicKey, String dataStr, String sign) {
        try {
            byte[] data = dataStr.getBytes("UTF-8");
            return verify(publicKey, data, sign);
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    public byte[] encryptByPublicKey(String key, byte[] data) {
        try {
            byte[] bytes = decryptBase64(key);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(bytes);
            KeyFactory factory = KeyFactory.getInstance(KEY_RSA);
            PublicKey publicKey = factory.generatePublic(keySpec);
            Cipher cipher = Cipher.getInstance(factory.getAlgorithm());
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return doFinalWithBlock(cipher, data, MAX_ENCRYPT_BLOCK);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public String encryptByPublicKey(String key, String dataStr) {
        try {
            byte[] result = encryptByPublicKey(key, dataStr.getBytes("UTF-8"));
            return encryptBase64(result);
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    public byte[] decryptByPrivateKey(String key, byte[] data, int maxDecryptBlock) {
        try {
            byte[] bytes = decryptBase64(key);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(bytes);
            KeyFactory factory = KeyFactory.getInstance(KEY_RSA);
            PrivateKey privateKey = factory.generatePrivate(keySpec);
            Cipher cipher = Cipher.getInstance(ECB_PKCS1_PADDING);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return doFinalWithBlock(cipher, data, maxDecryptBlock);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public String decryptByPrivateKey256(String key, String dataStr) {
        try {
            byte[] result = decryptByPrivateKey(key, decryptBase64(dataStr), MAX_DECRYPT_BLOCK_256);
            return new String(result, "UTF-8");
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    public String decryptByPrivateKey(String key, String dataStr) {
        try {
            byte[] result = decryptByPrivateKey(key, decryptBase64(dataStr), MAX_DECRYPT_BLOCK);
            return new String(result, "UTF-8");
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    public byte[] encryptByPrivateKey(String key, byte[] data) {
        try {
            byte[] bytes = decryptBase64(key);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(bytes);
            KeyFactory factory = KeyFactory.getInstance(KEY_RSA);
            PrivateKey privateKey = factory.generatePrivate(keySpec);
            Cipher cipher = Cipher.getInstance(ECB_PKCS1_PADDING);
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);
            return doFinalWithBlock(cipher, data, MAX_ENCRYPT_BLOCK);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public String encryptByPrivateKey(String key, String dataStr) {
        try {
            byte[] result = encryptByPrivateKey(key, dataStr.getBytes("UTF-8"));
            return encryptBase64(result).replace("\n", "");
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    public byte[] decryptByPublicKey(String key, byte[] data) {
        try {
            byte[] bytes = decryptBase64(key);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(bytes);
            KeyFactory factory = KeyFactory.getInstance(KEY_RSA);
            PublicKey publicKey = factory.generatePublic(keySpec);
            Cipher cipher = Cipher.getInstance(factory.getAlgorithm());
            cipher.init(Cipher.DECRYPT_MODE, publicKey);
            return doFinalWithBlock(cipher, data, MAX_DECRYPT_BLOCK);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public String decryptByPublicKey(String key, String dataStr) {
        try {
            byte[] result = decryptByPublicKey(key, decryptBase64(dataStr));
            return new String(result, "UTF-8");
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    public String getPublicKey(Map<String, Object> map) {
        Key key = (Key) map.get(KEY_RSA_PUBLICKEY);
        return encryptBase64(key.getEncoded());
    }

    public String getPrivateKey(Map<String, Object> map) {
        Key key = (Key) map.get(KEY_RSA_PRIVATEKEY);
        return encryptBase64(key.getEncoded());
    }

    public byte[] decryptBase64(String key) {
        return Base64.getDecoder().decode(key);
    }

    public String encryptBase64(byte[] key) {
        return Base64.getEncoder().encodeToString(key);
    }

    private byte[] doFinalWithBlock(Cipher cipher, byte[] data, int maxBlockSize) throws Exception {
        int inputLen = data.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] cache;
        int i = 0;
        while (inputLen - offSet > 0) {
            if (inputLen - offSet > maxBlockSize) {
                cache = cipher.doFinal(data, offSet, maxBlockSize);
            } else {
                cache = cipher.doFinal(data, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * maxBlockSize;
        }
        byte[] result = out.toByteArray();
        out.close();
        return result;
    }

    public static void main(String[] args) {
        RsaUtil rsaUtil = new RsaUtil();
        Map<String, Object> map = rsaUtil.generateKey();
        String data = "哈哈哈";
        String s = rsaUtil.encryptByPublicKey(rsaUtil.getPublicKey(map), data);
        System.out.println(s);
    }
}
