package com.eebv.encrypt.util;
import org.apache.commons.io.IOUtils;

import javax.servlet.http.Part;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class KeysUtils {

	/**
	 * This method receives a SSL public key, extracts it and returns a java PublicKey object.
	 * @param part Part instance that was received within a multipart/form-data POST request.
	 * @return PublicKey instance.
	 * @throws InvalidKeySpecException Thrown for invalid Keys (invalid encoding, wrong length,
     * uninitialized, etc).
	 * @throws NoSuchAlgorithmException Thrown when a particular cryptographic algorithm is requested  but is not
     * available in the environment.
	 * @throws IOException Thrown when there's problem with a I/O operation.
	 */
	public static PublicKey loadPublicKey(Part part) throws InvalidKeySpecException, NoSuchAlgorithmException, IOException {
		//Get the part input stream
	    String publicKeyPem = IOUtils.toString(part.getInputStream(), StandardCharsets.UTF_8);
		//Delete the begin and end information from the key
		publicKeyPem = publicKeyPem.replace("-----BEGIN PUBLIC KEY-----", "")
								   .replace("-----END PUBLIC KEY-----", "")
								   .replaceAll("\\s", "");
		//Decodes the public key
		byte[] publicKeyDer = Base64.getDecoder().decode(publicKeyPem);
		//The algorithm to use is RSA
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		//Generate java public key
		return keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyDer));
	}

    /**
     * This method receives a SSL private key, extracts it and returns a java Private object.
     * @param part Part instance that was received within a multipart/form-data POST request.
     * @return PublicKey instance.
     * @throws InvalidKeySpecException Thrown for invalid Keys (invalid encoding, wrong length,
     * uninitialized, etc).
     * @throws NoSuchAlgorithmException Thrown when a particular cryptographic algorithm is requested  but is not
     * available in the environment.
     * @throws IOException Thrown when there's problem with a I/O operation.
     */
	public static PrivateKey loadPrivateKey(Part part) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        //Get the part input stream
	    String privateKeyPem = IOUtils.toString(part.getInputStream(), StandardCharsets.UTF_8);
        //Delete the begin and end information from the key
	    privateKeyPem = privateKeyPem.replace("-----BEGIN PRIVATE KEY-----", "")
						             .replace("-----END PRIVATE KEY-----", "")
						             .replaceAll("\\s", "");
        //Decodes the public key
	    byte[] privateKeyDer = Base64.getDecoder().decode(privateKeyPem);
        //The algorithm to use is RSA
	    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        //Generate java private key
		return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyDer));
	}
}
