package segment;



import java.security.Key;

import java.security.SecureRandom;

import javax.crypto.Cipher;

import javax.crypto.KeyGenerator;

public class segment {
	
	private final static String AES = "AES";
	private final static String charset = "UTF-8";
	private final static String defKey = "gddxbdhp";
	//8字节key长度   
	/***     * 加密     * @param plain  
	* @param keySeed     * @param charSet    
	* @return 输出密文 16进制     */
			public static String encrypt(String plain, String keySeed, String charSet)
			{
				try {
					byte[] byteContent = plain.getBytes(charSet);
					Cipher cipher = Cipher.getInstance(AES); 
					cipher.init(Cipher.ENCRYPT_MODE, getKey(keySeed));  
					byte[] buf = cipher.doFinal(byteContent);   
					// byte[]转16进制  
					StringBuffer sb = new StringBuffer();  
					for (int i = 0; i < buf.length; i++) { 
						String hex = Integer.toHexString(buf[i] & 0xFF); 
						if (hex.length() == 1) {  
							hex = '0' + hex;    
							}           
						sb.append(hex.toUpperCase());  
						}         
					return sb.toString();   
					} catch (Exception e) {  
						e.printStackTrace();  
						}   
				return null;  
						}       
			/***     * 解密 输入16进制的字符串     *      * @param layer 
			 *     * @param keySeed     * @param charSet     * @return 原文     */  
			public static String decrypt(String layer, String keySeed, String charSet) { 
				try {    
					byte[] byteContent = new byte[layer.length() / 2];    
					if (layer.length() < 1) {     
						return null;   
						}    
					// 将16进制转换为二进制      
					for (int i = 0; i < layer.length() / 2; i++) {   
						int high = Integer.parseInt(layer.substring(i * 2, i * 2 + 1), 16);   
						int low = Integer.parseInt(layer.substring(i * 2 + 1, i * 2 + 2), 16);   
						byteContent[i] = (byte) (high * 16 + low);    
						}       
					Cipher cipher = Cipher.getInstance(AES);     
					cipher.init(Cipher.DECRYPT_MODE, getKey(keySeed));  
					byte[] buf = cipher.doFinal(byteContent);   
					return new String(buf, charSet);     
					} 
				catch (Exception e)
				{     
					e.printStackTrace();  
					}     
				return null; 
				}   
			public static Key getKey(String keySeed) {    
				if (keySeed == null) {  
					keySeed = System.getenv("AES_SYS_KEY");    
					}    
				if (keySeed == null) {    
					keySeed = System.getProperty("AES_SYS_KEY");    
					}    
				if (keySeed == null || keySeed.trim().length() == 0) {   
					keySeed = "abcd1234!@#$";
					// 默认种子 
					}   
				try {    
					SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");  
					
					secureRandom.setSeed(keySeed.getBytes());     
					KeyGenerator generator = KeyGenerator.getInstance("AES");   
					generator.init(secureRandom);    
					return generator.generateKey();    
					}
				catch (Exception e)
				{  
						throw new RuntimeException(e);   
						} 
				}   
			
			
			public static void main(String[] args) {    
				String express="AES加密解密算法";  
				long start=System.currentTimeMillis();   
				String layer = segment.encrypt(express,defKey,charset);   
				long end =System.currentTimeMillis();
				
				System.out.println("加密时长:"+String.valueOf(end-start));  
				System.out.println("原文："+express); 
				System.out.println("密文："+layer);  
				String plain = segment.decrypt(layer,defKey,charset);    
				System.out.println("原文："+plain);  
				}
}
		

	
	

	
