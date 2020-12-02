package Routing;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

public class NILayer implements BaseLayer {

	public int nUpperLayerCount = 0;
	public String pLayerName = null;
	public BaseLayer p_UnderLayer = null;
	public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();

	int m_iNumAdapter;
	public static List<Pcap> m_AdapterObject = new ArrayList<>();
	public PcapIf device;
	public static List<PcapIf> m_pAdapterList;
	StringBuilder errbuf = new StringBuilder();

	public NILayer(String pName) {
		// super(pName);
		pLayerName = pName;
		m_pAdapterList = new ArrayList<PcapIf>();
		m_iNumAdapter = 0;
		SetAdapterList();
	}

	public void PacketStartDriver() {
		int snaplen = 64 * 1024; // Capture all packets, no trucation
		int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
		int timeout = 10 * 1000; // 10 seconds in millis
		m_AdapterObject.add(Pcap.openLive(m_pAdapterList.get(m_iNumAdapter).getName(), snaplen, flags, timeout, errbuf));
	}
	
	public PcapIf GetAdapterObject(int iIndex) {
		return m_pAdapterList.get(iIndex);
	}

	public void SetAdapterNumber(int iNum) {
		m_iNumAdapter = iNum;
		PacketStartDriver();
		Receive();
	}

	public void SetAdapterList() {
		int r = Pcap.findAllDevs(m_pAdapterList, errbuf);
		if (r == Pcap.NOT_OK || m_pAdapterList.isEmpty()) {
			System.err.printf("Can't read list of devices, error is %s", errbuf.toString());
			return;
		}
	}
	
	// port Number를 받아 해당 Network Card의 ip Address를 가져오는 함수
	public static String getIpAddress(int portNum) {
		String[] rawIpdata = m_pAdapterList.get(portNum).getAddresses().get(0).getAddr().toString().split("\\.");
		String ipString = rawIpdata[0].substring(7, rawIpdata[0].length()) + "." + rawIpdata[1] + "." + rawIpdata[2] + "."
				+ rawIpdata[3].substring(0, rawIpdata[3].length() - 1);
		
		return ipString;
	}
	
	// port Number를 받아 해당 Network Card의 Mac Address를 가져오는 함수
	public static String getMacAddress(int portNum) {
		byte[] macAddress = null;
		try {
			macAddress = m_pAdapterList.get(portNum).getHardwareAddress();
		} catch (IOException e) { e.printStackTrace(); }
		
		String macString = Translator.macToString(macAddress);
		
		return macString;
	}

	public boolean Send(byte[] input, int length, int portNum) {
		ByteBuffer buf = ByteBuffer.wrap(input);
		if (m_AdapterObject.get(portNum).sendPacket(buf) != Pcap.OK) {
			System.err.println(m_AdapterObject.get(portNum).getErr());
			return false;
		}
		return true;
	}

	public boolean Receive() {
		Receive_Thread thread = new Receive_Thread(m_AdapterObject.get(m_iNumAdapter), 
				this.GetUpperLayer(0), m_iNumAdapter);
		Thread obj = new Thread(thread);
		obj.start();

		return false;
	}

	@Override
	public void SetUnderLayer(BaseLayer pUnderLayer) {
		// TODO Auto-generated method stub
		if (pUnderLayer == null)
			return;
		p_UnderLayer = pUnderLayer;
	}

	@Override
	public void SetUpperLayer(BaseLayer pUpperLayer) {
		// TODO Auto-generated method stub
		if (pUpperLayer == null)
			return;
		this.p_aUpperLayer.add(nUpperLayerCount++, pUpperLayer);
		// nUpperLayerCount++;
	}

	@Override
	public String GetLayerName() {
		// TODO Auto-generated method stub
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
		// TODO Auto-generated method stub
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

class Receive_Thread implements Runnable {
	byte[] data;
	Pcap AdapterObject;
	BaseLayer UpperLayer;
	int portNum;

	public Receive_Thread(Pcap m_AdapterObject, BaseLayer m_UpperLayer, int portNum) {
		AdapterObject = m_AdapterObject;
		UpperLayer = m_UpperLayer;
		this.portNum = portNum;
	}

	@Override
	public void run() {
		while (true) {
			PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {
				public void nextPacket(PcapPacket packet, String user) {
					data = packet.getByteArray(0, packet.size());
					UpperLayer.Receive(data, portNum);
				}
			};
			AdapterObject.loop(100000, jpacketHandler, "");
		}
	}
}
