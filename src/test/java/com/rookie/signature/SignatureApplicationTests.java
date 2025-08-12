package com.rookie.signature;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.Map;

import static com.rookie.signature.RsaUtil.*;

@SpringBootTest
class SignatureApplicationTests {

    @Test
    void contextLoads() {
        Map<String,Object> map = generateKey();
        String data = "哈哈哈";
        String s = encryptByPublicKey((String)map.get(KEY_RSA_PUBLICKEY),data);
        System.out.println(s);
    }

}
