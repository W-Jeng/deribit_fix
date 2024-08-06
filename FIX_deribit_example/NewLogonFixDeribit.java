//*****NewLogonFixDeribit.java*****

import java.security.MessageDigest;
import java.security.*;
import java.util.Base64;
import java.security.SecureRandom;
import java.io.UnsupportedEncodingException;

//import org.apache.commons.codec.binary.Base64;
import java.util.Base64;
public class NewLogonFixDeribit {

    public static void main(String[] args) {
        String apiKey = "API-KEY";
        String apiSecret = "API-SECRET";
        SecureRandom random = new SecureRandom();
        byte bytes[] = new byte[32];
        random.nextBytes(bytes);
        String nonce = Base64.getEncoder().encodeToString(bytes);
        String rawData = System.currentTimeMillis() + "." + nonce;
        try {
       
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update((rawData + apiSecret).getBytes("UTF-8"));
        String sig = Base64.getEncoder().encodeToString(md.digest());

        System.out.println("Username: " + apiKey);
        System.out.println("RawData: " + rawData);
        System.out.println("Password: " + sig);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    }
}