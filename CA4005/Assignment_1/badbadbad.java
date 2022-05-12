import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class SymmetricEncryption {
	public static void main(String[] args) throws GeneralSecurityException, IOException {

		// generate key: password||salt
		String password = "awJ*g60%MCq2^rlt"; // strong: lower & uppercase
												// letters, numbers & symbols
		byte[] salt = generateRandom16ByteValue();
		byte[] key = getEncryptionKey(password, salt);
		System.out.println("Password: " + password);
		System.out.println("Key: " + DatatypeConverter.printHexBinary(key));

		// hash the key x200
		byte[] haskedKey = hashKey(key);
		System.out.println("AES key: " + DatatypeConverter.printHexBinary(haskedKey));
		Key AESkey = new SecretKeySpec(haskedKey, "AES");

		// generate the IV
		byte[] IVbytes = generateRandom16ByteValue();
		System.out.println("IV: " + DatatypeConverter.printHexBinary(IVbytes));
		IvParameterSpec IV = new IvParameterSpec(IVbytes);
		System.out.println();

		// import file
		Path path = Paths.get("C:\\Test\\SymmetricEncryption.zip");
		byte[] fileInBytes = Files.readAllBytes(path);

		// encrypt file
		int fileLength = fileInBytes.length;
		// calculate how much padding is needed
		int padding = 16 - (fileLength % 16);
		byte[] cipherBytes = encryptPlaintext(fileInBytes, AESkey, IV, padding);
		System.out.println("Encrypted: " + DatatypeConverter.printHexBinary(cipherBytes));

		/*decrypt file - for testing and save the resulting file 
		byte[] plainTextBytes = decryptCiphertext(cipherBytes, AESkey, IV);
		Path newPath = Paths.get("C:\\Test\\DecryptedFile.zip");
		Path file = Files.write(newPath, plainTextBytes, StandardOpenOption.CREATE_NEW);
		System.out.println();*/

		// encrypt the password
		int exponent = 65537;
		BigInteger modulus = new BigInteger(
				"c406136c12640a665900a9df4df63a84fc855927b729a3a106fb3f379e8e4190ebba442f67b93402e535b18a5777e6490e67dbee954bb02175e43b6481e7563d3f9ff338f07950d1553ee6c343d3f8148f71b4d2df8da7efb39f846ac07c865201fbb35ea4d71dc5f858d9d41aaa856d50dc2d2732582f80e7d38c32aba87ba9",
				16);
		BigInteger encryptedPassword = encryptPassword(password, exponent, modulus);
		System.out.println("Encrypted password: " + encryptedPassword.toString(16));
		
		// save everything into a file
		FileWriter assignment = new FileWriter("SymmetricEncryption.txt", false);
		BufferedWriter out = new BufferedWriter(assignment);
		out.write("Encrypted password: " + encryptedPassword.toString(16) + "\r\n");
		out.write("\r\n");
		out.write("Salt in hex: " + DatatypeConverter.printHexBinary(salt) + "\r\n");
		out.write("\r\n");
		out.write("IV in hex: " + DatatypeConverter.printHexBinary(IVbytes) + "\r\n");
		out.write("\r\n");
		out.write("Encrypted file: " + DatatypeConverter.printHexBinary(cipherBytes) + "\r\n");
		out.write("\r\n");
		out.close();
		assignment.close();
	}

	private static BigInteger encryptPassword(String password, int exponent, BigInteger modulus)
			throws UnsupportedEncodingException {
		BigInteger passwordToEncrypt = new BigInteger(password.getBytes("UTF-8"));
		String exponentInBytes = Integer.toBinaryString(exponent);
		BigInteger encryptedPassword = BigInteger.ONE;
		
		// using right to left variant
		for (int i = 0; i < exponentInBytes.length(); i++) {
			if (exponentInBytes.charAt(i) == '1')
				encryptedPassword = (encryptedPassword.multiply(passwordToEncrypt)).mod(modulus);
			passwordToEncrypt = (passwordToEncrypt.multiply(passwordToEncrypt)).mod(modulus);
		}
		return encryptedPassword;
	}

	/*private static byte[] decryptCiphertext(byte[] cipherBytes, Key AESkey, IvParameterSpec IV)
			throws GeneralSecurityException, UnsupportedEncodingException {
		Cipher decrypt = Cipher.getInstance("AES/CBC/NoPadding");
		decrypt.init(Cipher.DECRYPT_MODE, AESkey, IV);
		byte[] plainTextBytes = decrypt.doFinal(cipherBytes);
		return plainTextBytes;
	}*/

	private static byte[] encryptPlaintext(byte[] fileInBytes, Key AESkey, IvParameterSpec IV, int padding)
			throws GeneralSecurityException, UnsupportedEncodingException {
		Cipher encrypt = Cipher.getInstance("AES/CBC/NoPadding");
		encrypt.init(Cipher.ENCRYPT_MODE, AESkey, IV);

		// add the custom padding
		byte[] paddedFileToEncrypt = new byte[fileInBytes.length + padding];
		System.arraycopy(fileInBytes, 0, paddedFileToEncrypt, 0, fileInBytes.length);		
		// set leftmost bit to 1, then all zeros: 128 = 1000 0000
		paddedFileToEncrypt[fileInBytes.length] = (byte) 128;
		for (int i = fileInBytes.length + 1; i < paddedFileToEncrypt.length; i++) {
			paddedFileToEncrypt[i] = (byte) 0;
		}

		byte[] cipherBytes = encrypt.doFinal(paddedFileToEncrypt);
		return cipherBytes;
	}

	private static byte[] hashKey(byte[] key) throws NoSuchAlgorithmException {
		MessageDigest digest = MessageDigest.getInstance("SHA-256");
		byte[] hashedKey = key;
		for (int i = 1; i <= 200; i++) {
			hashedKey = digest.digest(hashedKey);
		}
		return hashedKey;
	}

	private static byte[] getEncryptionKey(String password, byte[] salt) throws UnsupportedEncodingException {
		byte[] passwordBytes = password.getBytes("UTF-8");
		byte[] key = new byte[passwordBytes.length + salt.length];
		System.arraycopy(passwordBytes, 0, key, 0, passwordBytes.length);
		System.arraycopy(salt, 0, key, passwordBytes.length, salt.length);
		return key;
	}

	private static byte[] generateRandom16ByteValue() {
		byte[] _16byteValue = new byte[16];

		Random rnd = new SecureRandom();
		rnd.nextBytes(_16byteValue);
		return _16byteValue;
	}
}