package Routing;

import java.util.ArrayList;

public class IPLayer implements BaseLayer{
	public int nUpperLayerCount = 0;
	public String pLayerName = null;
	public BaseLayer p_UnderLayer = null;
	public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();
	
	_IP_HEADER m_sHeader;
	
	private class _IP_ADDR {
		private byte[] addr = new byte[4];
		
		public _IP_ADDR() {
			this.addr[0] = (byte) 0x00;
			this.addr[1] = (byte) 0x00;
			this.addr[2] = (byte) 0x00;
			this.addr[3] = (byte) 0x00;
		}
		
		@Override
		public String toString() {
			String ipAddress = "";
			
			// addr에 가지고있는 byte를 가져와 Integer로 변환 후 .을 더함
			for (byte b : this.addr) {
				ipAddress += Integer.toString(b & 0xFF) + ".";
			}
			
			// 마지막에 붙은 "."은 제거하여 return
			return ipAddress.substring(0, ipAddress.length() - 1);
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
	
	public boolean Send(byte[] input, int length) {
		byte[] _IP_FRAME = ObjToByte(m_sHeader, input, input.length);
		
		return this.GetUnderLayer().Send(_IP_FRAME, _IP_FRAME.length);
	}
	
	public boolean Receive(byte[] input, int length) {
		
		// 기본 구현에서는 TCP와 IP Layer의 Receive가 동작하지 않음
		
		return true;
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
