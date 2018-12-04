package com.eebv.file.util;

import com.eebv.encrypt.util.AsymmetricEncryptUtils;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.servlet.http.Part;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class EncryptedFileUtils {

    //Change this with your information
    private static final String uploadPath = "D:\\Documents\\URU\\Seguridad\\SSL\\Java\\SSL\\portafolio\\";

    /**
     * Checks if the file exists.
     * @param name name of the file.
     * @return true if the file exists, otherwise false is returned.
     */
    public static boolean fileIsInRepository(String name) {
        System.out.println(uploadPath + name + ".txt");
        return new File(uploadPath + name + ".txt").exists();
    }
    /**
     * TL;DR: Old fashioned way to get a file's name.
     * @param part Part instance that was received within a multipart/form-data POST request.
     * @return file's name.
     */
    private static String getFileName(Part part) {
        for (String content : part.getHeader("content-disposition").split(";")) {
            if (content.trim().startsWith("filename")) {
                return content.substring(content.indexOf('=') + 1).trim().replace("\"", "");
            }
        }
        return null;
    }

    /**
     * Receives a file and saves it in the repository encrypted with the provided public key.
     * @param publicKey the public key to encrypt with
     * @param file file that'll be encrypted
     * @throws IOException Thrown when there's problem with a I/O operation.
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
    public static void saveEncrypted(PublicKey publicKey, Part file)
            throws IOException, IllegalBlockSizeException, InvalidKeyException,
            BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException
    {
        //Get file's input stream
        String content = IOUtils.toString(file.getInputStream (), StandardCharsets.UTF_8);
        //Encrypt the file and get it's input stream once it is encrypted
        InputStream stream = new ByteArrayInputStream(AsymmetricEncryptUtils.Encrypt(publicKey, content));
        //Creates a file in the repository path and with the file original name
        File targetFile = new File(uploadPath + getFileName(file));
        //Writes the encrypted stream in the new file
        FileUtils.copyInputStreamToFile(stream, targetFile);
    }

    /**
     * Receives a file name and retrieves from the repository, then it is decrypted with the provided private key.
     * @param privateKey the private key to decrypt with.
     * @param fileName Name of the file that'll be decrypted.
     * @return file content decrypted.
     * @throws IOException Thrown when there's problem with a I/O operation.
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
    public static String getEncrypted(PrivateKey privateKey, String fileName) throws Exception {
        InputStream initialStream = FileUtils.openInputStream
                (new File(uploadPath + fileName + ".txt"));
        //Get file's input stream
        InputStream stream = new ByteArrayInputStream(AsymmetricEncryptUtils.Decrypt(privateKey, IOUtils.toByteArray(initialStream)));
        return IOUtils.toString(stream, StandardCharsets.UTF_8);
    }
}
