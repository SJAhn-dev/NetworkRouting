package Base_ARP;

import java.lang.reflect.Array;
import java.util.ArrayList;


public class TCPLayer implements BaseLayer{
	public int nUpperLayerCount = 0;
	public String pLayerName = null;
	public BaseLayer p_UnderLayer = null;
	public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();
	
	_TCP_HEADER m_sHeader;
	
	private class _TCP_ADDR {
		private byte[] addr = new byte[2];
		
		public _TCP_ADDR() {
			this.addr[0] = (byte) 0x00;
			this.addr[1] = (byte) 0x00;
		}
	}
	
	private class _TCP_HEADER {
		_TCP_ADDR tcp_srcport;						// Source Port
		_TCP_ADDR tcp_dstport;						// Destination Port
		byte[] tcp_seq;								// Sequence number
		byte[] tcp_ack;								// Acknowledged Sequence
		byte tcp_offset;							// No use
		byte tcp_flag;								// Control flag
		byte[] tcp_window;							// No use
		byte[] tcp_cksum;							// Check sum
		byte[] tcp_urgptr;							// No use
		byte[] padding;								// Padding
		byte[] tcp_data;							// Additional Data Part
		
		public _TCP_HEADER() {						// Total 24 Bytes
			this.tcp_srcport = new _TCP_ADDR();		// 2 Bytes	/ 0~1
			this.tcp_dstport = new _TCP_ADDR();		// 2 Bytes	/ 2~3
			this.tcp_seq = new byte[4];				// 4 Bytes	/ 4~7
			this.tcp_ack = new byte[4];				// 4 Bytes	/ 8~11
			this.tcp_offset = (byte) 0x00;			// 1 Byte	/ 12
			this.tcp_flag = (byte) 0x00;			// 1 Byte	/ 13
			this.tcp_window = new byte[2];			// 2 Bytes	/ 14~15
			this.tcp_cksum = new byte[2];			// 2 Bytes	/ 16~17
			this.tcp_urgptr = new byte[2];			// 2 Bytes	/ 18~19
			this.padding = new byte[4];				// 4 Bytes	/ 20~23
		}
	}
	
	private void ResetHeader() {
		m_sHeader = new _TCP_HEADER();
	}

	public TCPLayer(String pName) {
		// super(pName);
		pLayerName = pName;
		ResetHeader();
	}
	
	private byte[] ObjToByte(_TCP_HEADER Header, byte[] input, int length) {
		byte[] buf = new byte[24 + length];
		
		System.arraycopy(Header.tcp_srcport.addr, 0, buf, 0, 2);
		System.arraycopy(Header.tcp_dstport.addr, 0, buf, 2, 2);
		System.arraycopy(Header.tcp_seq, 0, buf, 4, 4);
		System.arraycopy(Header.tcp_ack, 0, buf, 8, 4);
		buf[12] = Header.tcp_offset;
		buf[13] = Header.tcp_flag;
		System.arraycopy(Header.tcp_window, 0, buf, 14, 2);
		System.arraycopy(Header.tcp_cksum, 0, buf, 16, 2);
		System.arraycopy(Header.tcp_urgptr, 0, buf, 18, 2);
		System.arraycopy(Header.padding, 0, buf, 20, 4);
		
		if(length!=0)
			System.arraycopy(input, 0, buf, 24, length);
			
		return buf;
	}
	
	public boolean Send(byte[] input, int length) {
		byte[] _TCP_FRAME = ObjToByte(m_sHeader, input, length);
		
		return this.GetUnderLayer().Send(_TCP_FRAME, _TCP_FRAME.length);
	}
	
	public boolean Receive(byte[] input, int length) {
		
		// 기본 구현에서는 TCP와 IP Layer의 Receive가 동작하지 않음
		
		return false;
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
