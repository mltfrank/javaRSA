package com.mltfrank.JavaRSA.test;

import com.mltfrank.JavaRSA.RSAHelper;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;

/**
 * Created by Frank on 2016/3/29.
 */
public class TestRSAHelper {
    public void testKeyLoader(){
        try{
            RSAHelper test = RSAHelper.INSTANCE;
            test.loadPublicKey(new FileInputStream(new File("rsa_public_key.pem")));
            test.loadPrivateKey(new FileInputStream(new File("pkcs8_rsa_private_key.pem")));
            test.loadPublicKey(new File("rsa_public_key.pem"));
            test.loadPrivateKey(new File("pkcs8_rsa_private_key.pem"));
        }catch (Exception e){
            e.printStackTrace();
        }
    }

    public void testEncryptLong(){
        try {
            File inputRaw = new File("input");
            FileInputStream inputStream = new FileInputStream(inputRaw);
            byte[] rawContent = new byte[Integer.parseInt(Long.toString(inputRaw.length()))];
            inputStream.read(rawContent);

            byte[] ened = RSAHelper.INSTANCE.encryptLong(rawContent);
            BufferedOutputStream writer = new BufferedOutputStream(new FileOutputStream(new File("encrypted")));
            writer.write(ened);
            writer.flush();
            writer.close();
        }catch (Exception e){
            e.printStackTrace();
        }
    }

    public void testDecryptLong(){
        try{
            File file = new File("encrypted");
            byte[] encrypted = new byte[Integer.parseInt(Long.toString(file.length()))];
            FileInputStream inputStream = new FileInputStream(file);
            inputStream.read(encrypted);
            RSAHelper test = RSAHelper.INSTANCE;
            test.loadPrivateKey(new FileInputStream(new File("pkcs8_rsa_private_key.pem")));
            String str = new String(test.decryptLong(encrypted));
            System.out.println(str);
        }catch (Exception e){
            e.printStackTrace();
        }
    }

    public static void main(String[] args){
        TestRSAHelper test = new TestRSAHelper();
        test.testKeyLoader();
        test.testEncryptLong();
        test.testDecryptLong();
    }
}
