package Routing;

import java.awt.Color;
import java.awt.Container;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.List;
import java.util.Vector;
import javax.swing.*;
import javax.swing.border.*;
import javax.swing.table.DefaultTableModel;

import org.jnetpcap.PcapIf;

import Routing.ARPLayer._ARPCache_Entry;
import Routing.ARPLayer._Proxy_Entry;

public class RoutingDlg extends JFrame implements BaseLayer {
	public int nUpperLayerCount = 0;
	public String pLayerName = null;
	public BaseLayer p_UnderLayer = null;
	public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();
	private static LayerManager m_LayerMgr = new LayerManager();	
	
	DefaultTableModel RoutingTableModel;
	Vector<String> RoutingTableColumns = new Vector<String>();
	Vector<String> RoutingTableRows = new Vector<String>();
	
	DefaultTableModel ARPTableModel;
	Vector<String> ARPTableColumns = new Vector<String>();
	Vector<String> ARPTableRows = new Vector<String>();
	
	DefaultTableModel ProxyTableModel;
	Vector<String> ProxyTableColumns = new Vector<String>();
	Vector<String> ProxyTableRows = new Vector<String>();
	
	JTable RoutingTable;
	JTable ARPCacheTable;
	JTable proxyARPTable;
	
	// Main Interface
	Container Main_contentPane;
	JButton Main_RoutingTableAddButton;
	JButton Main_RoutingTableDeleteButton;
	JButton Main_ARPDeleteButton;
	JButton Main_ProxyAddButton;
	JButton Main_ProxyDeleteButton;
	
	// Route Add Interface
	JFrame Route_RouteAddFrame;
	Container Route_ContentPane;
	JTextField Route_DstField;
	JTextField Route_NetmaskField;
	JTextField Route_GatewayField;
	JCheckBox Route_UpCheckBox;
	JCheckBox Route_GatewayCheckBox;
	JCheckBox Route_HostCheckBox;
	JComboBox<String> Route_InterfaceComboBox;
	JButton Route_AddButton;
	JButton Route_CancelButton;
	
	// Proxy Add Interface
	JFrame Proxy_ProxyAddFrame;
	Container Proxy_ContentPane;
	JTextField Proxy_IpAddressField;
	JTextField Proxy_MacAddressField;
	JComboBox<String> Proxy_InterfaceComboBox;
	JButton Proxy_AddButton;
	JButton Proxy_CancelButton;
	
	public static void main(String[] args) throws SocketException {
		m_LayerMgr.AddLayer(new RoutingDlg("GUI"));
		m_LayerMgr.AddLayer(new ARPLayer("ARP"));
		m_LayerMgr.AddLayer(new EthernetLayer("ETHERNET"));
		m_LayerMgr.AddLayer(new NILayer("NI"));
		m_LayerMgr.AddLayer(new IPLayer("IP"));
		
		m_LayerMgr.ConnectLayers(" NI ( *ETHERNET ( *ARP +IP ( *GUI ) ) )");
		((NILayer) m_LayerMgr.GetLayer("NI")).InitializeAdapter();

	}
	
	public RoutingDlg(String pName) throws SocketException {
		pLayerName = pName;
		
		// staticRouting Table
		RoutingTableColumns.addElement("Destination");
		RoutingTableColumns.addElement("NetMask");
		RoutingTableColumns.addElement("Gateway");
		RoutingTableColumns.addElement("Flag");
		RoutingTableColumns.addElement("Interface");
		RoutingTableColumns.addElement("Metric");
		
		ARPTableColumns.addElement("IP Address");
		ARPTableColumns.addElement("Ethernet Address");
		ARPTableColumns.addElement("Interface");
		ARPTableColumns.addElement("Flag");
		
		ProxyTableColumns.addElement("IP Address");
		ProxyTableColumns.addElement("Ehternet Address");
		ProxyTableColumns.addElement("Interface");
		
		RoutingTableModel = new DefaultTableModel(RoutingTableColumns, 0);
		ARPTableModel = new DefaultTableModel(ARPTableColumns, 0);
		ProxyTableModel = new DefaultTableModel(ProxyTableColumns, 0);
		
		setTitle("Form1");
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setBounds(250, 250, 1100, 500);
		Main_contentPane = new JPanel();
		((JComponent) Main_contentPane).setBorder(new EmptyBorder(5, 5, 5, 5));
		setContentPane(Main_contentPane);
		Main_contentPane.setLayout(null);
		pLayerName = pName;
		
		JPanel staticRoutingPanel = new JPanel();
		staticRoutingPanel.setBorder(new TitledBorder(
				UIManager.getBorder("TitledBorder.border"), "Static Routing Table",
				TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		staticRoutingPanel.setBounds(10, 5, 600, 425);
		Main_contentPane.add(staticRoutingPanel);
		staticRoutingPanel.setLayout(null);

		RoutingTable = new JTable(RoutingTableModel);
		RoutingTable.setBounds(0, 0, 580, 365);
		RoutingTable.setShowGrid(false);

		JScrollPane RoutingTableScrollPane = new JScrollPane(RoutingTable);
		RoutingTableScrollPane.setBounds(10, 15, 580, 365);
		staticRoutingPanel.add(RoutingTableScrollPane);
		
		Main_RoutingTableAddButton = new JButton("Add");
		Main_RoutingTableAddButton.setBounds(210, 385, 80, 30);
		Main_RoutingTableAddButton.addActionListener(new buttonEventListener());
		staticRoutingPanel.add(Main_RoutingTableAddButton);

		Main_RoutingTableDeleteButton = new JButton("Delete");
		Main_RoutingTableDeleteButton.setBounds(310, 385, 80, 30);
		Main_RoutingTableDeleteButton.addActionListener(new buttonEventListener());
		staticRoutingPanel.add(Main_RoutingTableDeleteButton);
		
		// ARPCache Table
		JPanel ARPCachePanel = new JPanel();
		ARPCachePanel.setBorder(new TitledBorder(
				UIManager.getBorder("TitledBorder.border"), "ARP Cache Table",
				TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		ARPCachePanel.setBounds(620, 5, 450, 210);
		Main_contentPane.add(ARPCachePanel);
		ARPCachePanel.setLayout(null);

		ARPCacheTable = new JTable(ARPTableModel);
		ARPCacheTable.setBounds(0, 0, 580, 355);
		ARPCacheTable.setShowGrid(false);

		JScrollPane ARPTableScrollPane = new JScrollPane(ARPCacheTable);
		ARPTableScrollPane.setBounds(10, 15, 430, 150);
		ARPCachePanel.add(ARPTableScrollPane);
		
		Main_ARPDeleteButton = new JButton("Delete");
		Main_ARPDeleteButton.setBounds(190, 170, 80, 30);
		Main_ARPDeleteButton.addActionListener(new buttonEventListener());
		ARPCachePanel.add(Main_ARPDeleteButton);
		
		// ProxyARP Table
		JPanel ProxyARPPanel = new JPanel();
		ProxyARPPanel.setBorder(new TitledBorder(
				UIManager.getBorder("TitledBorder.border"), "Proxy ARP Table",
				TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		ProxyARPPanel.setBounds(620, 220, 450, 210);
		Main_contentPane.add(ProxyARPPanel);
		ProxyARPPanel.setLayout(null);
		
		proxyARPTable = new JTable(ProxyTableModel);
		proxyARPTable.setBounds(0, 0, 580, 355);
		proxyARPTable.setShowGrid(false);

		JScrollPane ProxyTableScrollPane = new JScrollPane(proxyARPTable);
		ProxyTableScrollPane.setBounds(10, 15, 430, 150);
		ProxyARPPanel.add(ProxyTableScrollPane);
		
		Main_ProxyAddButton = new JButton("Add");
		Main_ProxyAddButton.setBounds(140, 170, 80, 30);
		Main_ProxyAddButton.addActionListener(new buttonEventListener());
		ProxyARPPanel.add(Main_ProxyAddButton);
		
		Main_ProxyDeleteButton = new JButton("Delete");
		Main_ProxyDeleteButton.setBounds(240, 170, 80, 30);
		Main_ProxyDeleteButton.addActionListener(new buttonEventListener());
		ProxyARPPanel.add(Main_ProxyDeleteButton);

		setVisible(true);
	}
	
	class buttonEventListener implements ActionListener {
		@Override
		public void actionPerformed(ActionEvent e) {
			if (e.getSource() == Main_RoutingTableAddButton) {
				RouteAddFrame();
			}
			if (e.getSource() == Main_RoutingTableDeleteButton) {
				
			}
			if (e.getSource() == Main_ARPDeleteButton) {
				
			}
			if (e.getSource() == Main_ProxyAddButton) {
				ProxyAddFrame();
			}
			if (e.getSource() == Main_ProxyDeleteButton) {
				
			}
			if (e.getSource() == Route_AddButton) {
				
			}
			if (e.getSource() == Route_CancelButton) {
				
			}
			if (e.getSource() == Proxy_AddButton) {
				
			}
			if (e.getSource() == Proxy_CancelButton) {
				
			}
		}
	}
		
	public void RouteAddFrame() {
		Route_RouteAddFrame = new JFrame("Static Route Add");
		Route_RouteAddFrame.setBounds(250, 250, 400, 300);
		Route_ContentPane = Route_RouteAddFrame.getContentPane();
		Route_RouteAddFrame.setLayout(null);
		Route_RouteAddFrame.setVisible(true);
			
		// Destination
		JLabel Route_DstLabel = new JLabel("Destination");
		Route_DstLabel.setBounds(20, 25, 100, 30);
		Route_ContentPane.add(Route_DstLabel);
			
		Route_DstField = new JTextField();
		Route_DstField.setBounds(130, 25, 230, 30);
		Route_ContentPane.add(Route_DstField);
			
		// Network
		JLabel Route_NetmaskLabel = new JLabel("NetMask");
		Route_NetmaskLabel.setBounds(20, 60, 100, 30);
		Route_ContentPane.add(Route_NetmaskLabel);
			
		Route_NetmaskField = new JTextField();
		Route_NetmaskField.setBounds(130, 60, 230, 30);
		Route_ContentPane.add(Route_NetmaskField);
			
		// Gateway
		JLabel Route_GatewayLabel = new JLabel("Gateway");
		Route_GatewayLabel.setBounds(20, 95, 100, 30);
		Route_ContentPane.add(Route_GatewayLabel);
			
		Route_GatewayField = new JTextField();
		Route_GatewayField.setBounds(130, 95, 230, 30);
		Route_ContentPane.add(Route_GatewayField);
			
		// Flag
		JLabel Route_FlagLabel = new JLabel("Flag");
		Route_FlagLabel.setBounds(20, 130, 100, 30);
		Route_ContentPane.add(Route_FlagLabel);
			
		Route_UpCheckBox = new JCheckBox("UP", false);
		Route_UpCheckBox.setBounds(130, 130, 45, 30);
		Route_ContentPane.add(Route_UpCheckBox);
			
		Route_GatewayCheckBox = new JCheckBox("Gateway", false);
		Route_GatewayCheckBox.setBounds(180, 130, 75, 30);
		Route_ContentPane.add(Route_GatewayCheckBox);
			
		Route_HostCheckBox = new JCheckBox("Host", false);
		Route_HostCheckBox.setBounds(260, 130, 55, 30);
		Route_ContentPane.add(Route_HostCheckBox);
			
		// Interface
		JLabel Route_InterfaceLabel = new JLabel("Interface");
		Route_InterfaceLabel.setBounds(20, 165, 100, 30);
		Route_ContentPane.add(Route_InterfaceLabel);
		Route_InterfaceComboBox = new JComboBox<>();
		
//		List<PcapIf> l = ((NILayer) m_LayerMgr.GetLayer("NI")).m_pAdapterList;
//		for (int i = 0; i < l.size(); i++)
//			Route_InterfaceComboBox.addItem(l.get(i).getDescription() + " : " + l.get(i).getName());
			
		Route_InterfaceComboBox.setBounds(130, 165, 230, 30);
		Route_InterfaceComboBox.addActionListener(new buttonEventListener());
		Route_ContentPane.add(Route_InterfaceComboBox);// src address
		
		// Buttons
		Route_AddButton = new JButton("Add");
		Route_AddButton.setBounds(120, 210, 80, 30);
		Route_AddButton.addActionListener(new buttonEventListener());
		Route_ContentPane.add(Route_AddButton);
		
		Route_CancelButton = new JButton("Cancel");
		Route_CancelButton.setBounds(210, 210, 80, 30);
		Route_CancelButton.addActionListener(new buttonEventListener());
		Route_ContentPane.add(Route_CancelButton);
			
	}
	
	public void ProxyAddFrame() {
		Proxy_ProxyAddFrame = new JFrame("Proxy ARP Add");
		Proxy_ProxyAddFrame.setBounds(250, 250, 400, 300);
		Proxy_ContentPane = Proxy_ProxyAddFrame.getContentPane();
		Proxy_ProxyAddFrame.setLayout(null);
		Proxy_ProxyAddFrame.setVisible(true);
			
		// Destination
		JLabel Proxy_DstLabel = new JLabel("IP");
		Proxy_DstLabel.setBounds(20, 25, 100, 30);
		Proxy_ContentPane.add(Proxy_DstLabel);
			
		Proxy_IpAddressField = new JTextField();
		Proxy_IpAddressField.setBounds(130, 25, 230, 30);
		Proxy_ContentPane.add(Proxy_IpAddressField);		
			
		// Netmask
		JLabel Proxy_MacAddressLabel = new JLabel("MAC");
		Proxy_MacAddressLabel.setBounds(20, 60, 100, 30);
		Proxy_ContentPane.add(Proxy_MacAddressLabel);
		
		Proxy_MacAddressField = new JTextField();
		Proxy_MacAddressField.setBounds(130, 60, 230, 30);
		Proxy_ContentPane.add(Proxy_MacAddressField);
		
		
		// Interface
		JLabel Proxy_InterfaceLabel = new JLabel("Interface");
		Proxy_InterfaceLabel.setBounds(20, 95, 100, 30);
		Proxy_ContentPane.add(Proxy_InterfaceLabel);
		
		Proxy_InterfaceComboBox = new JComboBox<>();
		
//		List<PcapIf> l = ((NILayer) m_LayerMgr.GetLayer("NI")).m_pAdapterList;
//		for (int i = 0; i < l.size(); i++)
//			Proxy_InterfaceComboBox.addItem(l.get(i).getDescription() + " : " + l.get(i).getName());
		
		Proxy_InterfaceComboBox.setBounds(130, 95, 230, 30);
		Proxy_InterfaceComboBox.addActionListener(new buttonEventListener());
		Proxy_ContentPane.add(Proxy_InterfaceComboBox);// src address
		
		// Buttons
		Proxy_AddButton = new JButton("Add");
		Proxy_AddButton.setBounds(120, 210, 80, 30);
		Proxy_AddButton.addActionListener(new buttonEventListener());
		Proxy_ContentPane.add(Proxy_AddButton);
		
		Proxy_CancelButton = new JButton("Cancel");
		Proxy_CancelButton.setBounds(210, 210, 80, 30);
		Proxy_CancelButton.addActionListener(new buttonEventListener());
		Proxy_ContentPane.add(Proxy_CancelButton);
		
	}
	

	
	@Override
	public void SetUnderLayer(BaseLayer pUnderLayer) {
		if (pUnderLayer == null)
			return;
		this.p_UnderLayer = pUnderLayer;
	}

	@Override
	public void SetUpperLayer(BaseLayer pUpperLayer) {
		if (pUpperLayer == null)
			return;
		this.p_aUpperLayer.add(nUpperLayerCount++, pUpperLayer);
		// nUpperLayerCount++;
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
