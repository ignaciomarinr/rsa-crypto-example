import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.xml.bind.DatatypeConverter;

public class Test {
	public static final String inputTextFilename = "in.txt";
	public static final String skFilename = "private.key";
	public static final String pkFilename = "public.key";

	public static void main(String[] args) throws IOException, ClassNotFoundException {
		byte[] inputText = Files.readAllBytes(Paths.get(inputTextFilename));
		RSALibrary rsaLibrary = new RSALibrary();

		System.out.println("Input (hex): " + DatatypeConverter.printHexBinary(inputText));
		System.out.println("Input size (bytes): " + inputText.length + "\n");
		

		/* Generation */

		// Generate private and public key files.
		rsaLibrary.generateKeys();
		

		/* Encryption */

		// Read the public key.
		PublicKey pk = null;

		try (FileInputStream fis = new FileInputStream(pkFilename);
				ObjectInputStream ois = new ObjectInputStream(fis)) {
			pk = (PublicKey) ois.readObject();
		}

		System.out.println("Public key: " + pk + "\n");

		// Encrypt input text (public key).
		byte[] ciphertext = rsaLibrary.encrypt(inputText, pk);

		System.out.println("Ciphertext (hex): " + DatatypeConverter.printHexBinary(ciphertext));
		System.out.println("Ciphertext size (bytes): " + ciphertext.length + "\n");

		// Read the private key.
		PrivateKey sk = null;

		try (FileInputStream fis = new FileInputStream(skFilename);
				ObjectInputStream ois = new ObjectInputStream(fis)) {
			sk = (PrivateKey) ois.readObject();
		}

		//System.out.println("Private key: " + sk. + "\n");

		// Decrypt ciphertext (private key):
		byte[] plaintext = rsaLibrary.decrypt(ciphertext, sk);

		System.out.println("Plaintext (hex): " + DatatypeConverter.printHexBinary(plaintext));
		System.out.println("Plaintext size (bytes): " + plaintext.length + "\n");

		
		/* Signing */

		// Sign input text (private key).
		byte[] signedText = rsaLibrary.sign(inputText, sk);

		System.out.println("Signed text (hex): " + DatatypeConverter.printHexBinary(signedText));
		System.out.println("Signed text size (bytes): " + signedText.length + "\n");

		// Verify the sign (public key).
		System.out.println("Verify sign: " + rsaLibrary.verify(inputText, signedText, pk));
	}
}