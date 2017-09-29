import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.xml.bind.DatatypeConverter;

public class Test {
	public static void main(String[] args) throws IOException, ClassNotFoundException {
		byte[] inputText = Files.readAllBytes(Paths.get("in.txt"));
		RSALibrary rsaLibrary = new RSALibrary();
		rsaLibrary.generateKeys();
		PublicKey pk = null;
		PrivateKey sk = null;
		
		System.out.println("input.txt (hex): " + DatatypeConverter.printHexBinary(inputText));
		System.out.println("input.txt size (bytes): " + inputText.length);
		
		try (FileInputStream fis = new FileInputStream("public.key");
				ObjectInputStream ois = new ObjectInputStream(fis)) {
			pk = (PublicKey) ois.readObject();
		}
		
		byte[] ciphertext = rsaLibrary.encrypt(inputText, pk);
		
		System.out.println("Ciphertext (hex): " + DatatypeConverter.printHexBinary(ciphertext));
		System.out.println("Ciphertext size (bytes): " + ciphertext.length);
		
		try (FileInputStream fis = new FileInputStream("private.key");
				ObjectInputStream ois = new ObjectInputStream(fis)) {
			sk = (PrivateKey) ois.readObject();
		}
		
		byte[] plaintext = rsaLibrary.decrypt(ciphertext, sk);
		
		System.out.println("Plaintext (hex): " + DatatypeConverter.printHexBinary(plaintext));
		System.out.println("Plaintext size (bytes): " + plaintext.length);
		
		// FIRMA
		
		byte[] signedtext = rsaLibrary.sign(inputText, sk);
		
		System.out.println("Signedtext (hex): " + DatatypeConverter.printHexBinary(signedtext));
		System.out.println("Signedtext size (bytes): " + signedtext.length);
		
		
		System.out.println("Verify sign: " + rsaLibrary.verify(inputText/*new byte[]{0x48,0x4F,0x4C,0x41,0x0A}*/, signedtext, pk));
	}
}