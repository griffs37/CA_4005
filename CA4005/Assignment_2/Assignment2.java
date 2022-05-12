import java.math.BigInteger;
import java.nio.file.Files;
import java.security.*;
import java.security.NoSuchAlgorithmException;
import java.util.Random;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.spec.*;
import java.io.*;

// Refs used
// El gamal explained series (https://www.youtube.com/watch?v=iiukwTar6Fo)
// generate random value BigInt (https://stackoverflow.com/questions/2290057/how-to-generate-a-random-biginteger-value-in-java)
// El gamal notes (https://loop.dcu.ie/pluginfile.php/3737992/mod_resource/content/3/2.7.html)
// Extended Euclid example in java (https://introcs.cs.princeton.edu/java/99crypto/ExtendedEuclid.java.html)

public class Assignment2 {
	public static void main(String[] args) throws NoSuchAlgorithmException, IOException {

		// given values for primemod p and generator g
		BigInteger primeModulus = new BigInteger("b59dd79568817b4b9f6789822d22594f376e6a9abc0241846de426e5dd8f6eddef00b465f38f509b2b18351064704fe75f012fa346c5e2c442d7c99eac79b2bc8a202c98327b96816cb8042698ed3734643c4c05164e739cb72fba24f6156b6f47a7300ef778c378ea301e1141a6b25d48f1924268c62ee8dd3134745cdf7323",16);
		BigInteger generator = new BigInteger("44ec9d52c8f9189e49cd7c70253c2eb3154dd4f08467a64a0267c9defe4119f2e373388cfa350a4e66e432d638ccdc58eb703e31d4c84e50398f9f91677e88641a2d2f6157e2f4ec538088dcf5940b053c622e53bab0b4e84b1465f5738f549664bd7430961d3e5a2e7bceb62418db747386a58ff267a9939833beefb7a6fd68",16);

		// file to be digitally signed and hashed with SHA-256
		Path path = Paths.get("Assignment2.class");
		byte[] fileInBytes = Files.readAllBytes(path);
		MessageDigest digest = MessageDigest.getInstance("SHA-256");
		byte[] hashedFileInBytes = digest.digest(fileInBytes);

		// generate secret key x
		BigInteger secretKey = randomValueGen(primeModulus, 1);
		System.out.println("Secret key: " + secretKey.toString(16)+ "\n");

		// generate public key y 
        BigInteger y = generateY(generator, secretKey, primeModulus);
		System.out.println("Public key: " + y.toString(16) + "\n");
		BigInteger s = BigInteger.ZERO;
		BigInteger r = null;

		while (s.compareTo(BigInteger.ZERO) == 0) {
			BigInteger k = null;
			BigInteger multInverse = BigInteger.valueOf(-1); //1 < k < p-1 and gcd(k,p-1) = 1
			while (multInverse.compareTo(BigInteger.valueOf(-1)) == 0) {
				k = randomValueGen(primeModulus, 2);
				multInverse = calculateInverse(k, primeModulus);
			}
            r = generateR(generator, k, primeModulus); //r = gk (mod p)
			System.out.println("R: " + r.toString(16)+ "\n");
			s = generateS(hashedFileInBytes, secretKey, r, multInverse, primeModulus); //s = (H(m)-xr)k-1 (mod p-1)
			// if s == 0 break and restart
			//System.out.println("S: " + s.toString(16));
			//System.out.println("tst2");
		}
		System.out.println("S: " + s.toString(16));

		// write files
		FileWriter yFile = new FileWriter("y.txt", false); // no append with false
		FileWriter rFile = new FileWriter("r.txt", false);
        FileWriter sFile = new FileWriter("s.txt", false);
        yFile.write("Public key: " + y.toString(16));
		rFile.write("R: " + r.toString(16));
		sFile.write("S: " + s.toString(16));
		yFile.close();
		rFile.close();
		sFile.close();

		//tests
		//System.out.println(r.compareTo(primeModulus));  0 < r < p and 0 < s < p-1
		//System.out.println(s.compareTo(primeModulus.subtract(BigInteger.ONE)));

	}

    public static BigInteger generateY(BigInteger generator, BigInteger secretKey, BigInteger modulus) {
        BigInteger y = generator.modPow(secretKey, modulus); // y = gx (mod p)
        return y;
    }

    public static BigInteger generateR(BigInteger generator, BigInteger k, BigInteger modulus) {
        BigInteger r = generator.modPow(k, modulus); // r = gk (mod p)
        return r;
    }

    public static BigInteger generateS(byte[] plaintext, BigInteger secretKey, BigInteger r, BigInteger k, BigInteger modulus) {
        BigInteger xr = secretKey.multiply(r); 
        BigInteger hashedFile = new BigInteger(1, plaintext);
        BigInteger s = ((hashedFile.subtract(xr)).multiply(k).mod(modulus.subtract(BigInteger.ONE))); // (h(m) - xr)
        return s;
    }
	// Method calculateGCD returns the GCD of the given val1 and val2
	public static BigInteger[] calculateGCD(BigInteger a, BigInteger N) {
		// extended euclid 
		if (N.equals(BigInteger.ZERO))
			return new BigInteger[] { a, BigInteger.ONE, BigInteger.ZERO };
		
		BigInteger[] d_x_y = calculateGCD(N, a.mod(N));
		BigInteger x = d_x_y[2];
		BigInteger d = d_x_y[0];
		BigInteger y = d_x_y[1].subtract((a.divide(N)).multiply(d_x_y[2]));
		return new BigInteger[] {d,x,y};
	}

	private static BigInteger randomValueGen(BigInteger primeModulus, int min) { // used for generating x and k values
		Random rand = new Random();
		BigInteger randomVal;
		do {
			randomVal = new BigInteger(primeModulus.bitLength(), rand);
		} 
		while (randomVal.compareTo(primeModulus.subtract(BigInteger.ONE)) != -2 && randomVal.compareTo(BigInteger.valueOf(min)) != 1);
		return randomVal;
	}
	
	//Method calculateInverse returns the modular inverse of the given val using the given modulus
	private static BigInteger calculateInverse(BigInteger k, BigInteger primeModulus) {
		BigInteger[] testMI = calculateGCD(k, primeModulus.subtract(BigInteger.ONE)); // test if gcd(a, n) == 1

		if (!testMI[0].equals(BigInteger.ONE)) { // test if mi exists
			return BigInteger.valueOf(-1);
		}
		if (testMI[1].compareTo(BigInteger.ZERO) == 1) // test if mi is a negative value
			return testMI[1];
		else
			return testMI[1].add(primeModulus);
	}
}