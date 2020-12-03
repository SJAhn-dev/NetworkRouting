package Routing;

import java.util.ArrayList;
import java.util.Hashtable;

public class ARPLayer implements BaseLayer{
	public int nUpperLayerCount = 0;
	public String pLayerName = null;
	public BaseLayer p_UnderLayer = null;
	public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();
	
	_ARP_HEADER m_sHeader;
	
	// ARP Cache Table & Proxy Table
	public static Hashtable<String, _ARPCache_Entry> _ARPCache_Table = new Hashtable<>();
	public static Hashtable<String, _Proxy_Entry> _Proxy_Table = new Hashtable<>();
	
	// BroadCast Message Mac/IP
	private final byte[] _BroadCast_Mac = {(byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF};
	private final byte[] _BroadCast_Ip = {(byte) 0x00, (byte)0x00, (byte)0x00, (byte)0x00};
	
	// Device's Info
	public byte[][] myIpAddress = new byte[2][4];
	public byte[][] myMacAddress = new byte[2][6];
	
	// ARP Cache Entry
	// Ip 주소는 Table에서 Key로 가지고 있으므로 Mac Address와 Status, lifeTime만 보유
	public static class _ARPCache_Entry {
		byte[] addr;
		String status;
		String arp_interface;
		
		public _ARPCache_Entry(byte[] addr, String status, String arp_interface) {  // boolena status -> string status 수정 
			this.addr = addr;
			this.status = status;
			this.arp_interface = arp_interface;
		}
	}
	
	// Proxy Entry
	// Ip주소는 Table에서 Key로 가지고 있으므로 Mac Address와 hostName만 보유
	public static class _Proxy_Entry {
		String hostName;
		byte[] addr;
		
		public _Proxy_Entry(byte[] addr, String hostName) {
			this.hostName = hostName;
			this.addr = addr;
		}
	}
	
	private void ResetHeader() {
		m_sHeader = new _ARP_HEADER();
	}
	
	public ARPLayer(String pName) {
		// super(pName);
		pLayerName = pName;
		ResetHeader();
	}
	
	// 각 Port의 mac Address와 Ip Address 저장하는 함수
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
	
	private class _IP_ADDR {
		private byte[] addr = new byte[4];
		
		public _IP_ADDR() {
			this.addr[0] = (byte) 0x00;
			this.addr[1] = (byte) 0x00;
			this.addr[2] = (byte) 0x00;
			this.addr[3] = (byte) 0x00;
		}
	}
	
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
		
	private class _ARP_HEADER {
		byte[] macType;								// Hardware Type
		byte[] ipType;								// Protocol Type
		byte macAddrLen;							// Length of hardware Address
		byte ipAddrLen;								// Length of protocol Address
		byte[] opcode;								// Opcode (ARP Request)
		_ETHERNET_ADDR srcMac;						// Sender's hardware Address
		_IP_ADDR srcIp;								// Sender's protocol Address
		_ETHERNET_ADDR dstMac;						// Target's hardware Address
		_IP_ADDR dstIp;								// Target's protocol Address
		
		public _ARP_HEADER() {						// 28 Bytes
			this.macType = new byte[2];				// 2 Bytes / 0 ~ 1
			this.ipType = new byte[2];				// 2 Bytes / 2 ~ 3
			this.macAddrLen = (byte) 0x00;			// 1 Byte  / 4
			this.ipAddrLen = (byte) 0x00;			// 1 Byte  / 5
			this.opcode = new byte[2];				// 2 Bytes / 6 ~ 7 
			this.srcMac = new _ETHERNET_ADDR();		// 6 Bytes / 8 ~ 13 
			this.srcIp = new _IP_ADDR();			// 4 Bytes / 14 ~ 17
			this.dstMac = new _ETHERNET_ADDR();		// 6 Bytes / 18 ~ 23
			this.dstIp = new _IP_ADDR();			// 4 Bytes / 24 ~ 27
		}
	}
	
	// Header를 Byte 배열로 변환하는 ObjToByte 함수
	private byte[] ObjToByte(_ARP_HEADER Header, byte[] input, int length) {
		byte[] buf = new byte[28 + length];
		
		System.arraycopy(Header.macType, 0, buf, 0, 2);
		System.arraycopy(Header.ipType, 0, buf, 2, 2);
		buf[4] = Header.macAddrLen;
		buf[5] = Header.ipAddrLen;
		System.arraycopy(Header.opcode, 0, buf, 6, 2);
		System.arraycopy(Header.srcMac.addr, 0, buf, 8, 6);
		System.arraycopy(Header.srcIp.addr, 0, buf, 14, 4);
		System.arraycopy(Header.dstMac.addr, 0, buf, 18, 6);
		System.arraycopy(Header.dstIp.addr, 0, buf, 24, 4);
		
		if(length != 0)
			System.arraycopy(input, 0, buf, 28, length);
				
		return buf;
	}
	
	public synchronized boolean Send(byte[] input, int length, int portNum) {
		// 먼저 자신이 가지고있는 ARP Cache인지 확인
		byte[] dstIpByte = new byte[4];
		String dstIp = null;
		String nextHop = null;
		System.arraycopy(input, 16, dstIpByte, 0, 4);
		dstIp = Translator.ipToString(dstIpByte);
		nextHop = IPLayer.nextHopAddress(dstIp);
		_ARP_HEADER packet = new _ARP_HEADER();
		
		if(containsARP(nextHop)) {
			// 
			_ARPCache_Entry tempEntry = _ARPCache_Table.get(nextHop);
			if(tempEntry.status.equals("Incomplete")) {	
				// Incomplete 상태라 Request 보내야하는경우
				setSrcIp(packet, portNum);
				setSrcMac(packet, portNum);
				setDstIp(packet, Translator.ipToByte(nextHop));
				setDstMac(packet, _BroadCast_Mac);
				setDefaultHeader(packet, (byte) 0x01);
				byte[] _ARP_FRAME = ObjToByte(packet, new byte[18], 18);
				this.GetUnderLayer().Send(_ARP_FRAME, _ARP_FRAME.length, portNum);
				arpThread thread = new arpThread(nextHop, input, input.length, portNum);
				Thread obj = new Thread(thread);
				obj.start();
			}
			else {	
				// ARP Request 보낼 필요 없는경우
				EthernetLayer.targetEnetAddress[portNum] = tempEntry.addr;
				this.GetUnderLayer().Send(input, input.length, portNum);
			}
		}
		else {
			// 자신이 가지고있지 않은 ARP Cache면 ARP Request 메세지를 보낸다
			_ARPCache_Table.put(nextHop, new _ARPCache_Entry(new byte[6], "Incomplete", Integer.toString(portNum)));
			setSrcIp(packet, portNum);
			setSrcMac(packet, portNum);
			setDstIp(packet, Translator.ipToByte(nextHop));
			setDstMac(packet, _BroadCast_Mac);
			setDefaultHeader(packet, (byte) 0x01);
			byte[] _ARP_FRAME = ObjToByte(packet, new byte[18], 18);
			this.GetUnderLayer().Send(_ARP_FRAME, _ARP_FRAME.length, portNum);
			_ARPCache_Entry entry = new _ARPCache_Entry(new byte[6], "Incomplete", Integer.toString(portNum));
			RoutingDlg.addArpCacheToTable(nextHop, entry);
			
			// ARP Message 연결이 될때까지 Thread에 메세지를 올려놓고 대기
			arpThread thread = new arpThread(nextHop, input, input.length, portNum);
			Thread obj = new Thread(thread);
			obj.start();
			return true;
		}
		return false;
	}
	
	// ARP 연결이 될때까지 Send를 대기시키는 Thread
	class arpThread implements Runnable {
		String nextIp;
		byte[] input;
		int length;
		int portNum;
		ARPLayer arpLayer;
		
		public arpThread(String nextIp, byte[] input, int length, int portNum) {
			this.nextIp = nextIp;
			this.input = input;
			this.length = length;
			this.portNum = portNum;
		}

		@Override
		public void run() {
			while(true) {
				// ARP값이 Complete가 되면 Ethernet Layer로 ICMP 메세지를 Send
				_ARPCache_Entry temp = _ARPCache_Table.get(nextIp);
				if(temp.status.equals("Complete")){
					EthernetLayer.targetEnetAddress[portNum] = temp.addr;
					GetUnderLayer().Send(input, input.length, portNum);
					break;
				}
			}
		}
	}
		
	// Gratuitous Send
	public boolean gratSend(String input, int portNum) {
		byte[] myMac = myMacAddress[portNum];
		setSrcIp(this.m_sHeader, portNum);
		setSrcMac(this.m_sHeader,myMac);
		setDstIp(this.m_sHeader,_BroadCast_Ip);
		setDstMac(this.m_sHeader,_BroadCast_Mac);
		setDefaultHeader(this.m_sHeader,(byte) 0x01);
		byte[] _ARP_FRAME = ObjToByte(m_sHeader, null, 0);
		this.GetUnderLayer().Send(_ARP_FRAME, _ARP_FRAME.length, portNum);
		
		return false;
	}
	
	public synchronized boolean Receive(byte[] input, int portNum) {
		byte[] srcIp = new byte[4];
		byte[] srcMac = new byte[6];
		byte[] dstIp = new byte[4];
		byte[] dstMac = new byte[6];
		System.arraycopy(input, 8, srcMac, 0, 6);
		System.arraycopy(input, 14, srcIp, 0, 4);
		System.arraycopy(input, 18, dstMac, 0, 6);
		System.arraycopy(input, 24, dstIp, 0, 4);
		
		// 자신의 Address & Network 내부 ARP 잡음 제거
		if(Translator.ipToString(srcIp).equals(Translator.ipToString(myIpAddress[0])))
			return false;
		if(Translator.ipToString(srcIp).equals(Translator.ipToString(myIpAddress[1])))
			return false;
		if(Translator.ipToString(srcIp).equals("192.168.1.255"))
			return false;
		if(Translator.ipToString(srcIp).equals("192.168.2.255"))
			return false;
		
		if(input[7] == 0x01) {
			// input으로 들어온 Message가 ARP Request Message인 경우 혹은 Proxy일경우
			if(isTargetMe(dstIp, portNum) || isItMyProxy(dstIp)) {
				if(containsARP(Translator.ipToString(srcIp))){
					_ARPCache_Entry entry = new _ARPCache_Entry(srcMac,"Complete", Integer.toString(portNum));
					_ARPCache_Table.put(Translator.ipToString(srcIp), entry);
					sendReply(input, input.length, portNum);
					RoutingDlg.addArpCacheToTable(Translator.ipToString(srcIp), entry);
				}
			}
			// ARP Request가 자신과 상관없는 Broadcast or Gratuitous인 경우
			else {
				if(_ARPCache_Table.containsKey(Translator.ipToString(srcIp))) {
					_ARPCache_Entry entry = _ARPCache_Table.get(Translator.ipToString(srcIp));
					System.arraycopy(srcMac, 0, entry.addr, 0, 6);
				}
				else if(!isMyGrat(srcIp) && !containsARP(Translator.ipToString(srcIp))) {
					_ARPCache_Entry entry = new _ARPCache_Entry(srcMac,"Complete", Integer.toString(portNum));
					_ARPCache_Table.put(Translator.ipToString(srcIp), entry);
					RoutingDlg.addArpCacheToTable(Translator.ipToString(srcIp), entry);
				}
			}
		}
		else if(input[7] == 0x02) {
			// input으로 들어온 Message가 ARP Reply인 경우
			if(isTargetMe(dstIp, portNum)) {
				_ARPCache_Entry entry = _ARPCache_Table.get(Translator.ipToString(srcIp));
				entry.addr = srcMac;
				entry.status = "Complete";
				RoutingDlg.addArpCacheToTable(Translator.ipToString(srcIp), entry);
			}
		}
		return false;
	}
	
	// Reply Message를 보내는 함수
	public void sendReply(byte[] input, int length, int portNum) {
		byte[] buf = new byte[length];
		System.arraycopy(input, 0, buf, 0, length);
		for(int idx = 0; idx < 6; idx++) {
			buf[idx+18] = myMacAddress[portNum][idx];
		}
		byte[] replyBuf = swaping(buf);
		replyBuf[7] = (byte) 0x02;
		this.GetUnderLayer().Send(replyBuf, replyBuf.length);
	}
	
	// 자신이 보낸 Grat Message인지 확인하는 함수
	public boolean isMyGrat(byte[] inputIp) {
		for(int cnt = 0; cnt < 2; cnt++) {
			boolean check = true;
			for(int idx = 0; idx < 4; idx++) {
				if(inputIp[idx] != myIpAddress[cnt][idx])
					check = false;
			}
			if(!check)
				return false;
		}
		return true;
	}
	
	// Proxy Table에 Proxy Entry 추가하는 함수
	public void addProxy(String ipInput, String macInput, String name) {
		byte[] macAddress = Translator.macToByte(macInput);
		_Proxy_Entry proxy = new _Proxy_Entry(macAddress, name);
		_Proxy_Table.put(ipInput, proxy);
	}
	
	// ARP Header의 기본값들을 채워주는 함수 + opcode
	public void setDefaultHeader(_ARP_HEADER header, byte opcode) {
		header.macType[1] = (byte) 0x01;
		header.ipType[0] = (byte) 0x08;
		header.ipType[1] = (byte) 0x00;
		header.ipAddrLen = (byte) 0x04;
		header.macAddrLen = (byte) 0x06;
		header.opcode[1] = opcode;
	}

	// ARPCache Table이 ip에 해당되는 Element를 가지고있는지 검사
	public boolean containsARP(String ip) {
		if(_ARPCache_Table.containsKey(ip)) 
			return true;
		else
			return false;
	}
	
	// Proxy Table이 ip input에 해당되는 Element를 가지고있는지 검사
	public boolean containsProxy(String ip) {
		if(_Proxy_Table.containsKey(ip))
			return true;
		else
			return false;
	}
	
	// m_sHeader의 mac Address를 본인의 Mac으로 채우는 함수
	public void setSrcMac(_ARP_HEADER header, int portNum) {
		System.arraycopy(myMacAddress[portNum], 0, header.srcMac.addr, 0, 6);
	}
	
	public void setSrcMac(_ARP_HEADER header, byte[] input) {
		System.arraycopy(input, 0, header.srcMac.addr, 0, 6);
	}
	
	// m_sHeader의 ip Address를 본인의 IP로 채우는 함수
	public void setSrcIp(_ARP_HEADER header, int portNum) {
		System.arraycopy(myIpAddress[portNum], 0, header.srcIp.addr, 0, 4);
	}
	
	// m_sHeader의 dst ip를 input 값으로 채우는 함수
	public void setDstIp(_ARP_HEADER header, byte[] input) {
		System.arraycopy(input, 0, header.dstIp.addr, 0, 4);
	}
	
	// m_sHeader의 dst Mac를 input 값으로 채우는 함수
	public void setDstMac(_ARP_HEADER header, byte[] input) {
		System.arraycopy(input, 0, header.dstMac.addr, 0, 6);
	}
		
	// input으로 받은 IP를 자신의 IP와 비교하는 함수
	public boolean isTargetMe(byte[] input, int portNum) {
		for(int idx = 0; idx < 4; idx++) {
			if(input[idx] != myIpAddress[portNum][idx])
				return false;
		}
		return true;
	}
	
	// src와 dst의 Mac, Ip Address Swap하는 함수
	private byte[] swaping(byte[] input) {
		byte[] buf = new byte[input.length];
		
		System.arraycopy(input, 0, buf, 0, input.length);
		// Mac 주소 스왑
		for(int idx = 0; idx < 6; idx++) {
			buf[idx + 8] = input[idx + 18];
			buf[idx + 18] = input[idx + 8];
		}
		
		// IP 주소 스왑
		for(int idx = 0; idx < 4; idx++) {
			buf[idx + 14] = input[idx + 24];
			buf[idx + 24] = input[idx + 14];
		}
		
		return buf;
	}
	
	// 수신한 ARP Message의 Ip주소가 자신이 보유하고 있는 Proxy의 Ip인지 검사하는 함수
	private boolean isItMyProxy(byte[] input) {
		if(_Proxy_Table.containsKey(Translator.ipToString(input))) 
			return true;
		
		return false;
	}

	// BaseLayer Function
	
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
