package com.mltfrank.JavaRSA;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import sun.misc.BASE64Decoder;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;

/**
 * RSA encrypt and decrypt tools based on bouncycastle library.
 * A RSA asymmetric encryption is implemented.
 * Support the encryption of byte arrays longer than public/private keys by subsection processing.
 * Before use this class, user must generate
 *
 * Created by Frank on 2016/3/29.
 */
public enum RSAHelper {
    INSTANCE;

    private static final int MAX_ENCRTPT_BYTE = 128; // count of byte to be encrypted, must less than (MAX_DECRTPT_BYTE-11)
    private static final int MAX_DECRTPT_BYTE = 256; // count of byte to be decrypted
    private static final int KEY_LENGTH = MAX_DECRTPT_BYTE * 8; // length of key(count in bit), must be the same to MAX_DECRTPT_BYTE.

    private RSAPrivateKey privateKey;

    private RSAPublicKey publicKey;

    public RSAPrivateKey getPrivateKey(){
        return this.privateKey;
    }

    public void setPrivateKey(RSAPrivateKey privateKey){
        this.privateKey = privateKey;
    }

    public RSAPublicKey getPublicKey(){
        return this.publicKey;
    }

    public void setPublicKey(RSAPublicKey publicKey){
        this.publicKey = publicKey;
    }

    /**
     * Generate key pair randomly.
     * After call this method, the private key and public key will be stored in the
     * attributes 'privateKey' and 'publicKey'.</br>
     * Use get method to get keys if needed.
     */
    public void genKeyPair(){
        KeyPairGenerator keyPairGen= null;
        try {
            keyPairGen= KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        keyPairGen.initialize(KEY_LENGTH, new SecureRandom());
        KeyPair keyPair= keyPairGen.generateKeyPair();
        this.privateKey= (RSAPrivateKey) keyPair.getPrivate();
        this.publicKey= (RSAPublicKey) keyPair.getPublic();
    }

    /**
     * Read public key from file
     * @param publicKeyFile public key file DWords.
     * @throws Exception during
     */
    public void loadPublicKey(File publicKeyFile) throws Exception{
        loadPublicKey(new FileInputStream(publicKeyFile));
    }

    /**
     * Read public key from input stream
     * @param in input stream to read public key
     * @throws Exception during
     */
    public void loadPublicKey(InputStream in) throws Exception{
        try {
            BufferedReader br= new BufferedReader(new InputStreamReader(in));
            String readLine= null;
            StringBuilder sb= new StringBuilder();
            while((readLine= br.readLine())!=null){
                if(readLine.charAt(0)=='-'){
                    continue;
                }else{
                    sb.append(readLine);
                    sb.append('\r');
                }
            }
            loadPublicKey(sb.toString());
        } catch (IOException e) {
            throw new IOException("Error when read public key from input stream");
        }
    }

    /**
     * load public key from string
     * @param publicKeyStr public key string
     * @throws Exception
     */
    public void loadPublicKey(String publicKeyStr) throws Exception{
        try {
            BASE64Decoder base64Decoder= new BASE64Decoder();
            byte[] buffer= base64Decoder.decodeBuffer(publicKeyStr);
            KeyFactory keyFactory= KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpec= new X509EncodedKeySpec(buffer);
            this.publicKey= (RSAPublicKey) keyFactory.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException e) {
            throw new Exception("No such algorithm in key factory");
        } catch (InvalidKeySpecException e) {
            throw new Exception("Invalid key spec, only support X509");
        } catch (IOException e) {
            throw new Exception("Error when read public key from string");
        }
    }

    /**
     * Read private key from file
     * @param privateKeyFile private key file DWords.
     * @throws Exception during
     */
    public void loadPrivateKey(File privateKeyFile) throws Exception{
        loadPrivateKey(new FileInputStream(privateKeyFile));
    }

    /**
     * load private key from input stream
     * @param in inputStream to read private string
     * @throws Exception
     */
    public void loadPrivateKey(InputStream in) throws Exception{
        try {
            BufferedReader br= new BufferedReader(new InputStreamReader(in));
            String readLine= null;
            StringBuilder sb= new StringBuilder();
            while((readLine= br.readLine())!=null){
                if(readLine.charAt(0)=='-'){
                    continue;
                }else{
                    sb.append(readLine);
                    sb.append('\r');
                }
            }
            loadPrivateKey(sb.toString());
        } catch (IOException e) {
            throw new IOException("Error when read private key from input stream");
        }
    }

    /**
     * load private key from string
     * @param privateKeyStr private key string
     * @throws Exception
     */
    public void loadPrivateKey(String privateKeyStr) throws Exception{
        try {
            BASE64Decoder base64Decoder= new BASE64Decoder();
            byte[] buffer= base64Decoder.decodeBuffer(privateKeyStr);
            PKCS8EncodedKeySpec keySpec= new PKCS8EncodedKeySpec(buffer);
            KeyFactory keyFactory= KeyFactory.getInstance("RSA");
            this.privateKey= (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException e) {
            throw new Exception("No such algorithm in key factory");
        } catch (InvalidKeySpecException e) {
            throw new Exception("Invalid key spec, only support PKCS8");
        } catch (IOException e) {
            throw new Exception("Error when read private key from input string");
        }
    }

    /**
     * Encrypt a byte array
     * The length of plant data is constrained by MAX_ENCRTPT_BYTE, if too long, a exception is thrown out.
     * If want to encrypt a long data, use method 'encryptLong'
     * @param plainTextData plant data bytes
     * @return encrypted bytes
     * @throws Exception exception with error message
     */
    public byte[] encrypt(byte[] plainTextData) throws Exception{
        if(publicKey== null){
            throw new Exception("Null public key, please generate or set first.");
        }
        try {
            Cipher cipher= Cipher.getInstance("RSA", new BouncyCastleProvider());
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return cipher.doFinal(plainTextData);
        } catch (NoSuchAlgorithmException e) {
            throw new Exception("No such algorithm in key factory");
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
            return null;
        }catch (InvalidKeyException e) {
            throw new Exception("Invalid key spec, only support X509");
        } catch (IllegalBlockSizeException e) {
            throw new Exception("Input byte array is too long, must be less than "+MAX_ENCRTPT_BYTE);
        } catch (BadPaddingException e) {
            throw new Exception("Broken input data");
        }
    }

    /**
     * Decrypt a byte array
     * The length of secret data is constrained by MAX_DECRTPT_BYTE, if too long, a exception is thrown out.
     * If want to decrypt a long data, use method 'decryptLong'
     * @param cipherData secret data
     * @return plant bytes
     * @throws Exception Exception exception with error message
     */
    public byte[] decrypt(byte[] cipherData) throws Exception{
        if (privateKey== null){
            throw new Exception("Null private key, please generate or set first.");
        }
        try {
            Cipher cipher= Cipher.getInstance("RSA", new BouncyCastleProvider());
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return cipher.doFinal(cipherData);
        } catch (NoSuchAlgorithmException e) {
            throw new Exception("No such algorithm in key factory");
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
            return null;
        }catch (InvalidKeyException e) {
            throw new Exception("Invalid key spec, only support PKCS8");
        } catch (IllegalBlockSizeException e) {
            throw new Exception("Input byte array is too long, must be less than "+MAX_DECRTPT_BYTE);
        } catch (BadPaddingException e) {
            throw new Exception("Broken input data");
        }
    }

    private void copySubarray(byte[] source, int start, int length, byte[] target){
        try{
            for(int i = 0; i < length; i ++){
                target[i] = source[i+start];
            }
        } catch (IndexOutOfBoundsException e){
            return;
        }
    }

    private void saveSubArray(byte[] source, int start, int length, byte[] target){
        try{
            for(int i = 0; i < length; i ++){
                target[start+i] = source[i];
            }
        } catch(IndexOutOfBoundsException e){
            return;
        }
    }

    /**
     * Encrypt a long byte array.
     * Encrypt in segment, if want to decrypt the result by other program,
     * decrypt it in segment too.
     * @param plainTextData plant text
     * @return decrypted data
     */
    public byte[] encryptLong(byte[] plainTextData){
        int length = plainTextData.length;
        int index = 0;
        byte[] buffer = new byte[MAX_ENCRTPT_BYTE];
        ArrayList<byte[]> result = new ArrayList<byte[]>();
        int totalLength = 0;
        try {
            // store encrypted segment into result array, and count the final length of encrypted array
            while (index < length) {
                if (index + MAX_ENCRTPT_BYTE <= length) {  // reach end
                    copySubarray(plainTextData, index, MAX_ENCRTPT_BYTE, buffer);
                } else {
                    buffer = new byte[length - index];
                    copySubarray(plainTextData, index, length - index, buffer);
                }
                byte[] res = encrypt(buffer);
                if(res == null){
                    throw new Exception("Broken data");
                }
                totalLength += res.length;
                result.add(res);
                index += MAX_ENCRTPT_BYTE;
            }
            // new a long final result and fill it with segement
            byte[] finalRes = new byte[totalLength];
            int finalIndex = 0;
            for(byte[] res : result){
                saveSubArray(res, finalIndex, res.length, finalRes);
                finalIndex += res.length;
            }
            return finalRes;
        } catch (Exception e){
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Decrypt a long byte array.
     * Do it in segement.
     * @param encryptTextData encrypted data
     * @return plant data
     */
    public byte[] decryptLong(byte[] encryptTextData){
        int length = encryptTextData.length;
        int index = 0;
        byte[] buffer = new byte[MAX_DECRTPT_BYTE];
        StringBuilder sb = new StringBuilder();
        try {
            // decrypted segment by segment, and write into a string buffer.
            while (index < length) {
                if (index + MAX_DECRTPT_BYTE <= length) {  // reach end
                    copySubarray(encryptTextData, index, MAX_DECRTPT_BYTE, buffer);
                } else {
                    copySubarray(encryptTextData, index, length - index, buffer);
                }
                byte[] res = decrypt(buffer);
                if(res == null){
                    throw new Exception("Broken data");
                }
                sb.append(new String(res));
                index += MAX_DECRTPT_BYTE;
            }
            return sb.toString().getBytes();
        } catch (Exception e){
            e.printStackTrace();
            return null;
        }
    }
}
