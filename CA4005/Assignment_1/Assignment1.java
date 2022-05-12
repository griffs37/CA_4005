import java.math.BigInteger;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.*;

// Resources used
// AES encryption walkthrough (https://www.baeldung.com/java-aes-encryption-decryption)
// RSA walkthrough (https://www.baeldung.com/java-rsa)
// more AES (https://howtodoinjava.com/java/java-security/aes-256-encryption-decryption/)
// interfaces info (https://www.geeksforgeeks.org/interfaces-in-java/)

// given interface
interface Assignment1Interface {
    
    /* Method generateKey returns the key as an array of bytes and is generated from the given password and salt. */
    
    byte[] generateKey(byte[] password, byte[] salt);
    
    /* Method encryptAES returns the AES encryption of the given plaintext as an array of bytes using the given iv and key */
        
    byte[] encryptAES(byte[] plaintext, byte[] iv, byte[] key) throws NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, NoSuchPaddingException, InvalidAlgorithmParameterException;
    
    /* Method decryptAES returns the AES decryption of the given ciphertext as an array of bytes using the given iv and key */
    
    byte[] decryptAES(byte[] ciphertext, byte[] iv, byte[] key) throws NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, NoSuchPaddingException, InvalidAlgorithmParameterException;
            
    /* Method encryptRSA returns the encryption of the given plaintext using the given encryption exponent and modulus */
    
    byte[] encryptRSA(byte[] plaintext, BigInteger exponent, BigInteger modulus);
    
    /* Method modExp returns the result of raising the given base to the power of the given exponent using the given modulus */
    
    BigInteger modExp(BigInteger base, BigInteger exponent, BigInteger modulus);
    
}
    
class Assignment1 implements Assignment1Interface {

    public byte[] generateKey(byte[] password, byte[] salt) {
        byte[] key = new byte[password.length + salt.length];
        System.arraycopy(password, 0, key, 0, password.length);
        System.arraycopy(salt, 0, key, password.length, salt.length);
        return key;
    }


    public byte[] encryptAES(byte[] plaintext, byte[] iv, byte[] key) throws NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, NoSuchPaddingException, InvalidAlgorithmParameterException {
        // calculate padding
        byte[] cipherBytes = new byte[0];
        int fileLength = plaintext.length;
        int padding = 16 - (fileLength % 16);
        // AES encryption
        Key AESkey = new SecretKeySpec(key, "AES");
        IvParameterSpec _IV = new IvParameterSpec(iv);
        Cipher encrypt = Cipher.getInstance("AES/CBC/NoPadding");
        encrypt.init(Cipher.ENCRYPT_MODE, AESkey, _IV);
        // add padding
		byte[] fileToEncrypt = new byte[plaintext.length + padding];
		System.arraycopy(plaintext, 0, fileToEncrypt, 0, plaintext.length);
		fileToEncrypt[plaintext.length] = (byte) 128;
		for (int i = plaintext.length + 1; i < fileToEncrypt.length; i++) {
			fileToEncrypt[i] = (byte) 0;
        }
        
		cipherBytes = encrypt.doFinal(fileToEncrypt);
        return cipherBytes;        
    }

    public byte[] decryptAES(byte[] ciphertext, byte[] iv, byte[] key) throws NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, NoSuchPaddingException, InvalidAlgorithmParameterException {

        Key AESkey = new SecretKeySpec(key, "AES");
		IvParameterSpec _IV = new IvParameterSpec(iv);

        Cipher decrypt = Cipher.getInstance("AES/CBC/NoPadding");
    	decrypt.init(Cipher.DECRYPT_MODE, AESkey, _IV);
    	byte[] plainTextBytes = decrypt.doFinal(ciphertext);
    	return plainTextBytes;
    }

    public byte[] encryptRSA(byte[] plaintext, BigInteger exponent, BigInteger modulus) {

        BigInteger passwordToEncrypt = new BigInteger(plaintext);
        BigInteger encryptedPassword = modExp(passwordToEncrypt, exponent, modulus);
        
        return encryptedPassword.toByteArray();
    }

    public BigInteger modExp(BigInteger base, BigInteger exponent, BigInteger modulus) {

        BigInteger encryptedPassword = BigInteger.ONE;
        String exponentInBytes = exponent.toString(2);
        for (int i = 0; i < exponentInBytes.length(); i++) {
            if (exponentInBytes.charAt(i) == '1')
                encryptedPassword = (encryptedPassword.multiply(base)).mod(modulus);
            base = (base.multiply(base)).mod(modulus);
        }
        System.out.println("encryptedPassword: " + encryptedPassword);

        return encryptedPassword;
    }

    public static void main(String[] args) throws GeneralSecurityException, IOException {

        Assignment1 obj = new Assignment1();
        // create password/salt
        byte[] password = "shPwi37*dd4ewdOoqwP".getBytes();
        byte[] salt = new byte[16];
        Random rnd = new SecureRandom();
        rnd.nextBytes(salt);
        byte[] key = obj.generateKey(password, salt);
        System.out.println("Password: " + password.toString());
        System.out.println("Key: " + new BigInteger(1, key).toString(16));

        // hash with SHA256
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashedKey = key;
        for (int i = 1; i <= 200; i++) {
            hashedKey = digest.digest(hashedKey);
        }
        System.out.println("AES key: " + new BigInteger(1, hashedKey).toString(16));

        // create initializaton vector 
        byte[] IVbytes = new byte[16];
        rnd.nextBytes(IVbytes);
        System.out.println("IV: " + new BigInteger(1, IVbytes).toString(16));
        Path path = Paths.get("test.zip");
        byte[] fileInBytes = Files.readAllBytes(path);

        // calculate padding
        int fileLength = fileInBytes.length;
        int padding = 16 - (fileLength % 16);
        byte[] fileToEncrypt = new byte[fileInBytes.length + padding];
        byte[] cipherBytes = obj.encryptAES(fileInBytes, IVbytes, hashedKey);

        // encrypt password using F4 exponent & public modulus given
        BigInteger exponent = BigInteger.valueOf(65537);
        BigInteger modulus = new BigInteger(
                "c406136c12640a665900a9df4df63a84fc855927b729a3a106fb3f379e8e4190ebba442f67b93402e535b18a5777e6490e67dbee954bb02175e43b6481e7563d3f9ff338f07950d1553ee6c343d3f8148f71b4d2df8da7efb39f846ac07c865201fbb35ea4d71dc5f858d9d41aaa856d50dc2d2732582f80e7d38c32aba87ba9",
                16);
        byte[] encryptedPassword = obj.encryptRSA(password, exponent, modulus);
        
        // save into files
        FileWriter saltFile = new FileWriter("Salt.txt");
        saltFile.write(new BigInteger(1, salt).toString(16));
        FileWriter ivFile = new FileWriter("IV.txt");
        ivFile.write(new BigInteger(1, IVbytes).toString(16));
        FileWriter passwordFile = new FileWriter("Password.txt");
        passwordFile.write(new BigInteger(1, encryptedPassword).toString(16));
        FileWriter encryptedFile = new FileWriter(args[0]);
        encryptedFile.write(new BigInteger(1, cipherBytes).toString(16));

        saltFile.close();
        ivFile.close();
        passwordFile.close();
        encryptedFile.close();
    }
}
