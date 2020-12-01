package Routing;

public class Translator {
	 // String Type IP 주소를 Byte로 변환
	 public static byte[] ipToByte(String ip) {
		 String[] ipBuf = ip.split("[.]");
		 byte[] buf = new byte[4];
		 
		 for(int idx = 0; idx < 4; idx++) {
			 buf[idx] = (byte) Integer.parseInt(ipBuf[idx]);
		 }
		 return buf;
	 }
	 
	 // String Type Mac 주소를 Byte로 변환
	 public static byte[] macToByte(String mac) {
		 String[] macBuf = mac.split("-");
		 byte[] buf = new byte[6];
		 for(int idx = 0; idx < 6; idx++) {
			 buf[idx] = (byte) (Integer.parseInt(macBuf[idx], 16) & 0xFF);
		 }
		 return buf;
	 }
	 
	// byte 배열로 된 mac 주소를 String으로 변환하는 함수
	public static String macToString(byte[] mac) {
		String macString = "";
		for (byte b : mac) {
			macString += String.format("%02X:", b);
		}
		return macString.substring(0, macString.length() - 1);
	}
		
	public static String ipToString(byte[] ip) {
		String ipAddress = "";
		for (byte b : ip) {
			ipAddress += Integer.toString(b & 0xFF) + ".";
		}
		return ipAddress.substring(0, ipAddress.length() - 1);
	}

}
