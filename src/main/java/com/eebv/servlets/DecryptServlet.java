package com.eebv.servlets;

import com.eebv.encrypt.util.KeysUtils;
import com.eebv.file.util.EncryptedFileUtils;
import org.apache.commons.io.IOUtils;
import org.json.JSONObject;

import javax.servlet.ServletException;
import javax.servlet.annotation.MultipartConfig;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.Part;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;

@WebServlet("/SSL/Decrypt")
@MultipartConfig
public class DecryptServlet extends HttpServlet {

    /**
     * This endpoint receives the name of the file that'll be decrypted and  the private key that'll be used to decrypt.
     * @param req servlet request
     * @param resp servlet response
     */
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        resp.setContentType("application/json");
        PrintWriter printWriter = resp.getWriter();
        JSONObject response = new JSONObject();
        try {
            Part fileNamePart = req.getPart("name"); //must be sent as "name" in the form-data
            Part privateKeyPart = req.getPart("private"); //must be sent as "private" in the form-data
            //check if all the files were sent in the request
            if (fileNamePart != null && privateKeyPart != null ) {
                //Get file name
                String fileName = IOUtils.toString(fileNamePart.getInputStream(), StandardCharsets.UTF_8);
                //check if the file exists in the repository
                if (EncryptedFileUtils.fileIsInRepository(fileName)) {
                    //Load private key
                    PrivateKey privateKey = KeysUtils.loadPrivateKey(privateKeyPart);
                    //Get the content of the file once it is decrypted
                    String content = EncryptedFileUtils.getEncrypted(privateKey, fileName);
                    response.put("status", 200);
                    response.put("data", content);
                } else {
                    response.put("status", 404);
                    response.put("error", "File with the provided name not found");
                }
            } else {
                response.put("status", 400);
                response.put("error", "Please send a private key and a file name");
            }
        } catch (InvalidKeySpecException | IllegalArgumentException e) {
            e.printStackTrace();
            response.put("status", 400);
            response.put("message", "Invalid Key");
        } catch (Exception e) {
            e.printStackTrace();
            response.put("status", 500);
            response.put("message", "Internal Server Error");
        }
        printWriter.print(response);
    }
}
