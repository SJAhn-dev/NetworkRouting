package Base_ARP;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.ArrayList;

public class EthernetLayer implements BaseLayer {
	public int nUpperLayerCount = 0;
	public String pLayerName = null;
	public BaseLayer p_UnderLayer = null;
	public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();
	
	_ETHERNET_HEADER m_sHeader = new _ETHERNET_HEADER(); // ethernet header생성자
	static byte[] myEnetAddress;

	private class _ETHERNET_ADDR {
		private byte[] addr = new byte[6];

		public _ETHERNET_ADDR() {
			this.addr[0] = (byte) 0x00;
			this.addr[1] = (byte) 0x00;
			this.addr[2] = (byte) 0x00;
			this.addr[3] = (byte) 0x00;
			this.addr[4] = (byte) 0x00;
			this.addr[5] = (byte) 0x00;
		}
	}

	private class _ETHERNET_HEADER {
		_ETHERNET_ADDR enet_dstaddr;
		_ETHERNET_ADDR enet_srcaddr;
		byte[] enet_type;
		byte[] enet_data;

		public _ETHERNET_HEADER() {							// 14 Bytes
			this.enet_dstaddr = new _ETHERNET_ADDR();		// 6 Bytes / 0 ~ 5
			this.enet_srcaddr = new _ETHERNET_ADDR();		// 6 Bytes / 6 ~ 11
			this.enet_type = new byte[2];					// 2 Bytes / 12 ~ 13
			this.enet_data = null;
		}
	}

	public EthernetLayer(String pName) {
		// super(pName);
		pLayerName = pName;
		ResetHeader();
		try {
			myEnetAddress = getLocalMacAddress();
		} catch (UnknownHostException | SocketException e) {
			e.printStackTrace();
		}
	}
		
	private void ResetHeader() {
		m_sHeader = new _ETHERNET_HEADER();
	}

	public boolean Send(byte[] input, int length) {
		byte[] bytes;
		m_sHeader.enet_data = input;
		
		if(input[7] == 0x01 || input[7] == 0x02) {
			// Opcode 0x0001
			// ARP Request or Reply Message => Protocol Type 0x0806
			m_sHeader.enet_type[0] = (byte) 0x08;
			m_sHeader.enet_type[1] = (byte) 0x06;
		}
		else {
			// Opcode 0x0000
			// Normal Data Message => Protocol Type 0x0800
			m_sHeader.enet_type[0] = (byte) 0x08;
			m_sHeader.enet_type[1] = (byte) 0x00;
		}
		
		setEthernetHeader(input);
		bytes = ObjToByte(m_sHeader, input, input.length);
		
		if(this.GetUnderLayer().Send(bytes, bytes.length))
			return true;
		else
			return false;
	}
	
	public boolean Receive(byte[] input) {
		byte[] buf;
		
		// Target이 자신도 아니고 BroadCast도 아닌 경우 drop
		if(!isTargetMe(input) && !isBroadCast(input)) 
			return false;
		
		if (input[12] == 0x08 && input[13] == 0x06) {
			// Receive한 Message가 ARP Message인 경우
			buf = removeEthernetHeader(input, input.length);
			this.GetUpperLayer(0).Receive(buf);
		}
		else if (input[12] == 0x08 && input[13] == 0x00) {
			// ARP Message 아닌 경우 IPLayer로 올린다
			buf = removeEthernetHeader(input, input.length);
			this.GetUpperLayer(1).Receive(buf);
		}
		else
			return false;
		
		return true;
	}
	
	// EthernetHeader 의 Addr을 ARP Header의 주소로 채운다
	public void setEthernetHeader(byte[] input) {
		System.arraycopy(input, 8, m_sHeader.enet_srcaddr.addr, 0, 6);
		System.arraycopy(input, 18, m_sHeader.enet_dstaddr.addr, 0, 6);
	}	
	
	// Ethernet Header를 Packet에서 제거해주는 함수
	private byte[] removeEthernetHeader(byte[] input, int length) {
		byte[] buf = new byte[length - 14];
		
		for(int idx = 0; idx < length - 14; idx++) {
			buf[idx] = input[idx + 14];
		}
		
		return buf;
	}
	
	// Receive한 Packet의 Dst Address가 자신인지 확인하는 함수
	private boolean isTargetMe(byte[] input) {
		for(int idx = 0; idx < 6; idx++) {
			if(input[idx] != myEnetAddress[idx])
				return false;
		}
		return true;
	}
	
	// Receive한 Packet이 BroadCast인지 확인하는 함수
	private boolean isBroadCast(byte[] input) {
		for(int idx = 0; idx < 6; idx++) {
			if(input[idx] != (byte) 0xFF)
				return false;
		}
		return true;
	}
	
	public byte[] ObjToByte(_ETHERNET_HEADER Header, byte[] input, int length) {
		byte[] buf = new byte[length + 14];
		
		System.arraycopy(Header.enet_dstaddr.addr, 0, buf, 0, 6);
		System.arraycopy(Header.enet_srcaddr.addr, 0, buf, 6, 6);
		System.arraycopy(Header.enet_type, 0, buf, 12, 2);

		System.arraycopy(input, 0, buf, 14, length);

		return buf;
	}
	
	// Local Mac Address 가져오는 함수
	 public byte[] getLocalMacAddress() throws UnknownHostException, SocketException {
			InetAddress ip;

			ip = InetAddress.getLocalHost();
			NetworkInterface network = NetworkInterface.getByInetAddress(ip);
			byte[] mac = network.getHardwareAddress();
			
			return mac;
	 }

	@Override
	public void SetUnderLayer(BaseLayer pUnderLayer) {
		if(pUnderLayer == null)
			return;
		this.p_UnderLayer = pUnderLayer;
	}

	@Override
	public void SetUpperLayer(BaseLayer pUpperLayer) {
		if(pUpperLayer == null)
			return;
		this.p_aUpperLayer.add(nUpperLayerCount++, pUpperLayer);
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
	public void SetUpperUnderLayer(BaseLayer pUULayer) {
		this.SetUpperLayer(pUULayer);
		pUULayer.SetUnderLayer(this);
	}
}
