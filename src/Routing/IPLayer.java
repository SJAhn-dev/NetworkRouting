package Routing;

import java.util.ArrayList;


public class IPLayer implements BaseLayer{
	public int nUpperLayerCount = 0;
	public String pLayerName = null;
	public BaseLayer p_UnderLayer = null;
	public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();
	
	_IP_HEADER m_sHeader;
	public byte[][] myIpAddress = new byte[2][4];
	public byte[][] myMacAddress = new byte[2][6];
	public static ArrayList<_Routing_Entry> _Routing_Table = new ArrayList<>();
	
	private class _IP_ADDR {
		private byte[] addr = new byte[4];
		public _IP_ADDR() {
			this.addr[0] = (byte) 0x00;
			this.addr[1] = (byte) 0x00;
			this.addr[2] = (byte) 0x00;
			this.addr[3] = (byte) 0x00;
		}
	}
	
	public static class _Routing_Entry {
		String dst;
		String netmask;
		String gateway;
		String flag;
		int routing_interface;
		String metric;
		
		public _Routing_Entry(String[] input) {
			this.dst = input[0];
			this.netmask = input[1];
			this.gateway = input[2];
			this.flag = input[3];
			this.routing_interface = Integer.parseInt(input[4]);
			this.metric = input[5];
		}
	}
	
	private class _IP_HEADER {
		byte ip_verlen;							// IP Version -> IPv4
		byte ip_tos;							// Type of Service
		byte[] ip_len;							// Total Packet Length
		byte[] ip_id;							// Datagram ID
		byte[] ip_fragoff;						// Fragment Offset
		byte ip_ttl;							// Time to live in gateway hops
		byte ip_proto;							// IP Protocol
		byte[] ip_cksum;						// Header Checksum
		_IP_ADDR ip_src;						// IP address of source
		_IP_ADDR ip_dst;						// IP address of destination
		byte[] ip_data;							// Variable length data
		
		public _IP_HEADER() {					// 20 Bytes
			this.ip_verlen = (byte) 0x00;		// 1 Byte	/ 0
			this.ip_tos = (byte) 0x00;			// 1 Byte	/ 1
			this.ip_len = new byte[2];			// 2 Bytes	/ 2~3
			this.ip_id = new byte[2];			// 2 Bytes	/ 4~5
			this.ip_fragoff = new byte[2];		// 2 Bytes 	/ 6~7
			this.ip_ttl = (byte) 0x00;			// 1 Byte	/ 8
			this.ip_proto = (byte) 0x00;		// 1 Byte	/ 9
			this.ip_cksum = new byte[2];		// 2 Bytes	/ 10~11
			this.ip_src = new _IP_ADDR();		// 4 Bytes	/ 12~15
			this.ip_dst = new _IP_ADDR();		// 4 Bytes	/ 16~19
		}
	}
	
	private void ResetHeader() {
		m_sHeader = new _IP_HEADER();
	}

	public IPLayer(String pName) {
		// super(pName);
		pLayerName = pName;
		ResetHeader();
	}
	
	public void initAddress() {
		String port0_mac = NILayer.getMacAddress(0);
		String port1_mac = NILayer.getMacAddress(1);
		myMacAddress[0] = Translator.macToByte(port0_mac);
		myMacAddress[1] = Translator.macToByte(port1_mac);
		
		String port0_ip = NILayer.getIpAddress(0);
		String port1_ip = NILayer.getIpAddress(1);
		myIpAddress[0] = Translator.ipToByte(port0_ip);
		myIpAddress[1] = Translator.ipToByte(port1_ip);
	}
	
	private byte[] ObjToByte(_IP_HEADER Header, byte[] input, int length) {
		byte[] buf = new byte[20 + length];
		buf[0] = Header.ip_verlen;
		buf[1] = Header.ip_tos;
		System.arraycopy(Header.ip_len, 0, buf, 2, 2);
		System.arraycopy(Header.ip_id, 0, buf, 4, 2);
		System.arraycopy(Header.ip_fragoff, 0, buf, 6, 2);
		buf[8] = Header.ip_ttl;
		buf[9] = Header.ip_proto;
		System.arraycopy(Header.ip_cksum, 0, buf, 10, 2);
		System.arraycopy(Header.ip_src.addr, 0, buf, 12, 4);
		System.arraycopy(Header.ip_dst.addr, 0, buf, 16, 4);
		System.arraycopy(input, 0, buf, 20, length);
		
		return buf;
	}
	
	// String 배열을 받아 Routing Table에 put하는 함수
	public void addToRoutingTable(String[] input) {
		_Routing_Entry entry = new _Routing_Entry(input);
		_Routing_Table.add(entry);
	}
	
	// targetKey를 받아 Routing Table에서 해당 데이터를 지우는 함수
	public void removeEntryFromRoutingTable(String targetKey) {
		for(int idx = 0; idx < _Routing_Table.size(); idx++) {
			_Routing_Entry temp = _Routing_Table.get(idx);
			if(temp.dst.equals(targetKey)) {
				_Routing_Table.remove(idx);
				return;
			}
		}
	}
	
	public boolean Send(byte[] input, int length, int portNum) {
		byte[] _IP_FRAME = ObjToByte(m_sHeader, input, input.length);
		return this.GetUnderLayer().Send(_IP_FRAME, _IP_FRAME.length, portNum);
	}
	
	public boolean Receive(byte[] input, int portNum) {
		byte[] dstIp = new byte[4];
		System.arraycopy(input, 16, dstIp, 0, 4);
		String dstIpStr = Translator.ipToString(dstIp);
		//System.out.println("IPLayer" + dstIpStr);
		
		// Routing Table 탐색
		for(int idx = 0; idx < _Routing_Table.size(); idx++) {
			_Routing_Entry temp = _Routing_Table.get(idx);
			String dstMasking = netMask(dstIpStr, temp.netmask);
			String nextAddress = null;
			
			// Destionation IP에 Masking한 Ip와 Table의 Ip가 동일한 경우 -> Gateway 존재
			if(temp.dst.equals(dstMasking)) {
				if(temp.flag.equals("U")) {
					nextAddress = dstIpStr;
				}
				else if (temp.flag.equals("UG")) {
					nextAddress = temp.gateway;
				}
			}
			// 다음 목적지 (nextHop) 찾았을 시 해당 hop와 연결된 gatewecay로 packet 전송
			if(nextAddress != null) {
				//System.out.println("IPLayer2" + input.length);
				this.GetUnderLayer().Send(input, input.length, temp.routing_interface);
				return true;
			}
		}
		
		return false;
	}
	
	public static String nextHopAddress(String dst) {
		for(int idx = 0; idx < _Routing_Table.size(); idx++) {
			_Routing_Entry temp = _Routing_Table.get(idx);
			String dstMasking = netMask(dst, temp.netmask);
			if(temp.dst.equals(dstMasking)) {
				if(temp.flag.equals("U")) {
					return dst;
				}
				else if (temp.flag.equals("UG")) {
					return temp.gateway;
				}
			}
		}
		return null;
	}
	
	public static String netMask(String input, String mask) {
		byte[] inputByte = Translator.ipToByte(input);
		byte[] maskByte = Translator.ipToByte(mask);
		
		byte[] masking = new byte[4];
		for(int idx = 0; idx < 4; idx++) {
			masking[idx] = (byte) (inputByte[idx] & maskByte[idx]);
		}
		
		return Translator.ipToString(masking);
	}

	@Override
	public String GetLayerName() {
		return pLayerName;
	}

	@Override
	public BaseLayer GetUnderLayer() {
		if (p_UnderLayer == null)
			return null;
		return p_UnderLayer;
	}

	@Override
	public BaseLayer GetUpperLayer(int nindex) {
		if (nindex < 0 || nindex > nUpperLayerCount || nUpperLayerCount < 0)
			return null;
		return p_aUpperLayer.get(nindex);
	}

	@Override
	public void SetUnderLayer(BaseLayer pUnderLayer) {
		if (pUnderLayer == null)
			return;
		p_UnderLayer = pUnderLayer;
	}

	@Override
	public void SetUpperLayer(BaseLayer pUpperLayer) {
		if (pUpperLayer == null)
			return;
		this.p_aUpperLayer.add(nUpperLayerCount++, pUpperLayer);
		// nUpperLayerCount++;
	}

	@Override
	public void SetUpperUnderLayer(BaseLayer pUULayer) {
		this.SetUpperLayer(pUULayer);
		pUULayer.SetUnderLayer(this);

	}

}
