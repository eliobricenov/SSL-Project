package com.eebv.servlets;

import com.eebv.encrypt.util.KeysUtils;
import com.eebv.file.util.EncryptedFileUtils;
import org.json.JSONObject;

import javax.servlet.annotation.MultipartConfig;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.Part;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

@WebServlet("/SSL/Encrypt")
@MultipartConfig
public class EncryptServlet extends HttpServlet {

    /**
     * This endpoint receives two files in the request, one is the file that'll be encrypted and the other one is
     * the key used to encrypt.
     * @param req servlet request
     * @param resp servlet response
     */
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        resp.setContentType("application/json");
        JSONObject response = new JSONObject();
        PrintWriter printWriter = resp.getWriter();
        try {
            Part publicKeyPart = req.getPart("public");
            Part secretPart = req.getPart("secret");
            //check if all the files were sent in the request
            if (publicKeyPart != null  && secretPart != null) {
                PublicKey publicKey = KeysUtils.loadPublicKey(publicKeyPart);
                EncryptedFileUtils.saveEncrypted(publicKey, secretPart);
                response.put("status", 200);
            } else {
                response.put("status", 400);
                response.put("error", "Please send a public key and a file");
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
