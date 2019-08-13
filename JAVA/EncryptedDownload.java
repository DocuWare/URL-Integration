import java.security.MessageDigest;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class EncryptedDownload 
{
	private static String passphrase = "DI4a2nR2K0pw0zGcz+3CoA=="; // Passphrase encoded base64
	
    private	static String parameters;
    
    private static Cipher ci = null;
    private static byte[] passphraseSHA512 = null;
	
	private static byte[] iv;
	private static byte[] passphrase_byte;

    private static String passphraseSub;
    private static String ivSub;
    
    public static void main(String[] args) throws Exception 
    {
    	Init();
    	SecretKeySpec sks = Get_Passphrase();
    	IvParameterSpec ivps = Get_IV();
		Init_Cypher(sks, ivps);
	}
 
    private static IvParameterSpec Get_IV()
    {
    	return new IvParameterSpec(iv);
    }
    
    private static SecretKeySpec Get_Passphrase() throws Exception
    {  	
    	return new SecretKeySpec(passphrase_byte, "AES");
    }
    
    private static void Init() throws Exception
    {
		ci = Cipher.getInstance("AES/CBC/PKCS5Padding");
    	MessageDigest md = MessageDigest.getInstance("SHA-512");
    	md.reset();
		
		//Decode passphrase
		//Replace this part with your preferred Bas64 decoder. java.util.Base64 exist in java since version 1.8
		byte [] plainPassphrase = java.util.Base64.getDecoder().decode(passphrase);

		System.out.println("Plain" + new String(plainPassphrase));

		passphraseSHA512 = md.digest(plainPassphrase);
		
		//Array copy keys
		int keySize = 256 / 8;
		int ivSize = 128 / 8;
		passphrase_byte = java.util.Arrays.copyOfRange(passphraseSHA512, 0, keySize);
		iv = java.util.Arrays.copyOfRange(passphraseSHA512, keySize, keySize + ivSize);

		//Encode dwLogin and the query to the required Base64URL
		String dwLogin = UrlTokenEncode("User=user\\nPwd=123456789".getBytes());
		String query = UrlTokenEncode("[DWDOCID]=1".getBytes());
		
		String fileCabinet = "4530fb79-ea98-44c3-b2cc-51627033f85f";
		String downloadType = "Download";

		String integrationElement = "D";

		String searchDialog = "38c19319-c3ae-4ed2-ab98-81122eb0a4d7";
		
    	parameters = "p=" + integrationElement + "&lc=" + dwLogin + "&fc=" + fileCabinet +"&q=" + query + "&dt=" + downloadType + "&sed=" + searchDialog; 
      }
    
    private static void Init_Cypher(SecretKeySpec sks, IvParameterSpec ivps) throws Exception
    {
    	ci.init(Cipher.ENCRYPT_MODE, sks, ivps);
		System.out.println(parameters);

    	byte[] ciphertext = ci.doFinal(parameters.getBytes("UTF-8"));
		
		System.out.println(ciphertext);

		String server = "https://petersengineering.docuware.cloud";
		//Encode ciphertext to Base64URL
		String encodedCiphertext = UrlTokenEncode(ciphertext)
    	String url = server + "/DocuWare/Platform/WebClient/1/Integration?ep=" + encodedCiphertext;
		
		System.out.println(url);
    }
   
	//https://www.oipapio.com/question-5674514
	public static String UrlTokenEncode(byte[] input) {
		try {
			if (input == null) {
			return null;
			}
   
			if (input.length < 1) {
				return null;
			}
   
			String base64Text = null;
			int endPos = 0;
			char[] base64Chars = null;

			//Replace this part with your preferred Bas64 encoder. java.util.Base64 exist in java since version 1.8
			base64Text = java.util.Base64.getEncoder().encodeToString(input);
			if (base64Text == null) {
				return null;
			}
   
			for (endPos = base64Text.length(); endPos > 0; endPos--) {
				if (base64Text.charAt(endPos - 1) != '=') {
					break;
				}
			}
   
			base64Chars = new char[endPos + 1];
			base64Chars[endPos] = (char) ((int) '0' + base64Text.length() - endPos);
			for (int iter = 0; iter < endPos; iter++) {
				char c = base64Text.charAt(iter);
				switch (c) {
					case '+':
						base64Chars[iter] = '-';
						break;
					case '/':
						base64Chars[iter] = '_';
						break;
					case '=':
						base64Chars[iter] = c;
					break;
					default:
						base64Chars[iter] = c;
					break;
				}
			}
			return new String(base64Chars);
		} catch (Exception e) {
			return null;
		}
   }
}