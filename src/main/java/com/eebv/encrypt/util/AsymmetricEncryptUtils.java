package com.eebv.encrypt.util;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class AsymmetricEncryptUtils {

    /**
     * Uses Cipher to encrypt a content with the provided public key.
     * @param pk public key to encrypt with.
     * @param content content that'll be encrypted.
     * @return bytes of the content once it is encrypted
     * @throws IllegalBlockSizeException Thrown if the input data is not a multiple of the block-size.
     * @throws InvalidKeyException Thrown for invalid Keys (invalid encoding, wrong length,
     * uninitialized, etc).
     * @throws BadPaddingException Thrown when a particular padding mechanism is expected for the input data but the
     * data is not padded properly.
     * @throws NoSuchAlgorithmException Thrown when a particular cryptographic algorithm is requested  but is not
     * available in the environment.
     * @throws NoSuchPaddingException Thrown when a particular padding mechanism is requested but
     * is not available in the environment.
     */
	public static byte[] Encrypt(PublicKey pk, String content) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException
    {
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, pk);
        return cipher.doFinal(content.getBytes(StandardCharsets.UTF_8));
	}

    /**
     * Uses Cipher to decrypt a content with the provided private key.
     * @param pk private key to decrypt with.
     * @param encrypted encrypted content that'll be decrypted.
     * @return bytes of the content once it is decrypted
     * @throws IllegalBlockSizeException Thrown if the input data is not a multiple of the block-size.
     * @throws InvalidKeyException Thrown for invalid Keys (invalid encoding, wrong length,
     * uninitialized, etc).
     * @throws BadPaddingException Thrown when a particular padding mechanism is expected for the input data but the
     * data is not padded properly.
     * @throws NoSuchAlgorithmException Thrown when a particular cryptographic algorithm is requested  but is not
     * available in the environment.
     * @throws NoSuchPaddingException Thrown when a particular padding mechanism is requested but
     * is not available in the environment.
     */
	public static byte[] Decrypt(PrivateKey pk, byte[] encrypted) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException
    {
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.DECRYPT_MODE, pk);
        return cipher.doFinal(encrypted);
	}

}
