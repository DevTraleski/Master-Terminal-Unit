import javax.crypto.*;
import java.security.*;
import javax.crypto.spec.SecretKeySpec;

import java.io.File;
import java.util.*;

public class Parser {

	private Map<String, String[]> rtus = new HashMap<String, String[]>();

	public Parser() {
		try {
			File file = new File("db");
			Scanner sc  = new Scanner(file);

			while(sc.hasNextLine()) {
				String[] array = sc.nextLine().split(":");
				String[] newArray = new String[2];
				newArray[0] = array[1];
				newArray[1] = array[2];
				rtus.put(array[0], newArray);
			}

			System.out.println(rtus.get("rtu_a")[0]);

		}
		catch (Exception e) {
			System.out.println(e);
		}
	}

	public static String asHex (byte buf[]) {
    		StringBuffer strbuf = new StringBuffer(buf.length * 2);
   		int i;

    		for (i = 0; i < buf.length; i++) {
        		if (((int) buf[i] & 0xff) < 0x10)
            			strbuf.append("0");

        		strbuf.append(Long.toString((int) buf[i] & 0xff, 16));
    		}

    		return strbuf.toString();
	}

	public byte[] encrypt(String rtu, String original) {

		try {
			byte[] key = rtus.get(rtu)[0].getBytes("UTF-8");
			SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");

			Cipher cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
			byte[] encrypted = cipher.doFinal(original.getBytes("UTF-8"));
			System.out.println("Encrypted: " + asHex(encrypted));
			return encrypted;
		} catch (Exception e) {
			System.out.println(e);
		}

		return new byte[0];
	}

	public String decrypt(String rtu, byte[] encrypted) {

		try {
			byte[] key = rtus.get(rtu)[0].getBytes("UTF-8");
			SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");

			Cipher decipher = Cipher.getInstance("AES");
			decipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
			byte[] original = decipher.doFinal(encrypted);
			String originalString = new String(original);
			System.out.println("Decrypted: " + originalString);
			return originalString;
		} catch (Exception e) {
			System.out.println(e);
		}

		return "FAIL";
	}

	public String decryptTOTP(String rtu, byte[] encrypted) {

		try {
			TimeBasedOneTimePasswordGenerator totp = new TimeBasedOneTimePasswordGenerator();

			String lmk = rtus.get(rtu)[0];
			String nonce = rtus.get(rtu)[1];
			byte[] key = (nonce + lmk).getBytes("UTF-8");
			MessageDigest sha = MessageDigest.getInstance("SHA-1");
			key = sha.digest(key);
			key = Arrays.copyOf(key, 16);
			SecretKey secretKey = new SecretKeySpec(key, "AES");

			final Date now = new Date();
			int totp_k = totp.generateOneTimePassword(secretKey, now);
			System.out.println("Decrypt TOTP: " + totp_k);

			sha = MessageDigest.getInstance("SHA-1");
			byte[] newKey = sha.digest(Integer.toString(totp_k).getBytes("UTF-8"));
			newKey = Arrays.copyOf(key, 16);

			SecretKeySpec secretKeySpec = new SecretKeySpec(newKey, "AES");
			Cipher decipher = Cipher.getInstance("AES");
			decipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
			byte[] original = decipher.doFinal(encrypted);
			String originalString = new String(original);
			System.out.println("Decrypted: " + originalString);
			return originalString;
		} catch (Exception e) {
			System.out.println(e);
		}

		return "FAIL";
	}

	public byte[] encryptTOTP(String rtu, String original) {

		try {
			TimeBasedOneTimePasswordGenerator totp = new TimeBasedOneTimePasswordGenerator();

			String lmk = rtus.get(rtu)[0];
			String nonce = rtus.get(rtu)[1];
			byte[] key = (nonce + lmk).getBytes("UTF-8");
			MessageDigest sha = MessageDigest.getInstance("SHA-1");
			key = sha.digest(key);
			key = Arrays.copyOf(key, 16);
			SecretKey secretKey = new SecretKeySpec(key, "AES");

			final Date now = new Date();
			int totp_k = totp.generateOneTimePassword(secretKey, now);
			System.out.println("Encrypt TOTP: " + totp_k);

			sha = MessageDigest.getInstance("SHA-1");
			byte[] newKey = sha.digest(Integer.toString(totp_k).getBytes("UTF-8"));
			newKey = Arrays.copyOf(key, 16);

			SecretKeySpec secretKeySpec = new SecretKeySpec(newKey, "AES");
			Cipher cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
			byte[] encrypted = cipher.doFinal(original.getBytes("UTF-8"));
			System.out.println("Encrypted: " + asHex(encrypted));
			return encrypted;
		} catch (Exception e) {
			System.out.println(e);
		}

		return new byte[0];
	}


}
