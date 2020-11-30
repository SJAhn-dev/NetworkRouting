package Routing;

import java.util.Hashtable;

public class RoutingTable {
	public static Hashtable<String, _Routing_Entry> _Routing_Table = new Hashtable<>();
	
	public static class _Routing_Entry {
		String dst;
		String netmask;
		String gateway;
		String flag;
		String routing_interface;
		String metric;
		
		public _Routing_Entry(String[] input) {
			this.dst = input[0];
			this.netmask = input[1];
			this.gateway = input[2];
			this.flag = input[3];
			this.routing_interface = input[4];
			this.metric = input[5];
		}
	}
	
	// String 배열을 받아 Routing Table에 put하는 함수
	public static void addToRoutingTable(String[] input) {
		_Routing_Entry entry = new _Routing_Entry(input);
		_Routing_Table.put(input[0], entry);
	}
	
	public static void removeEntryFromRoutingTable(String targetKey) {
		_Routing_Table.remove(targetKey);
	}
	
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
