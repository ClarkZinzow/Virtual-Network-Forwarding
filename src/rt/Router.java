package edu.wisc.cs.sdn.vnet.rt;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

import java.nio.ByteBuffer;
import java.util.Collection;
import java.util.Iterator;
import net.floodlightcontroller.packet.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Queue;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device
{	
	/** Routing table for the router */
	private RouteTable routeTable;
	
	/** ARP cache for the router */
	private ArpCache arpCache;
	
    private final short IPV4ETHERTYPE = 0x0800;

    private ConcurrentHashMap<Integer, ARPRequester> activeThreads = new ConcurrentHashMap<Integer, ARPRequester>();

	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */
	public Router(String host, DumpFile logfile)
	{
		super(host,logfile);
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache();
	}
	
	/**
	 * @return routing table for the router
	 */
	public RouteTable getRouteTable()
	{ return this.routeTable; }
	
	/**
	 * Load a new routing table from a file.
	 * @param routeTableFile the name of the file containing the routing table
	 */
	public void loadRouteTable(String routeTableFile)
	{
		if (!routeTable.load(routeTableFile, this))
		{
			System.err.println("Error setting up routing table from file "
					+ routeTableFile);
			System.exit(1);
		}
		
		System.out.println("Loaded static route table");
		System.out.println("-------------------------------------------------");
		System.out.print(this.routeTable.toString());
		System.out.println("-------------------------------------------------");
	}
	
	/**
	 * Load a new ARP cache from a file.
	 * @param arpCacheFile the name of the file containing the ARP cache
	 */
	public void loadArpCache(String arpCacheFile)
	{
		if (!arpCache.load(arpCacheFile))
		{
			System.err.println("Error setting up ARP cache from file "
					+ arpCacheFile);
			System.exit(1);
		}
		
		System.out.println("Loaded static ARP cache");
		System.out.println("----------------------------------");
		System.out.print(this.arpCache.toString());
		System.out.println("----------------------------------");
	}

    public ConcurrentHashMap<Integer, ARPRequester> getActiveThreads() {
	return activeThreads;
    }

    public Ethernet genArpReply(Ethernet etherPacket, Iface inIface) {
	ARP arpPacket = (ARP) etherPacket.getPayload();
	Ethernet ether = new Ethernet();
	ARP arpReplyPacket = new ARP();
	
	ether.setEtherType(Ethernet.TYPE_ARP);
	ether.setSourceMACAddress(inIface.getMacAddress().toBytes());
	ether.setDestinationMACAddress(etherPacket.getSourceMACAddress());

	arpReplyPacket.setHardwareType(ARP.HW_TYPE_ETHERNET);
	arpReplyPacket.setProtocolType(ARP.PROTO_TYPE_IP);

	arpReplyPacket.setHardwareAddressLength((byte)(Ethernet.DATALAYER_ADDRESS_LENGTH & 0xff));
	arpReplyPacket.setProtocolAddressLength((byte)4);

	arpReplyPacket.setOpCode(ARP.OP_REPLY);
	arpReplyPacket.setSenderHardwareAddress(inIface.getMacAddress().toBytes());
	arpReplyPacket.setSenderProtocolAddress(IPv4.toIPv4AddressBytes(inIface.getIpAddress()));
	arpReplyPacket.setTargetHardwareAddress(arpPacket.getSenderHardwareAddress());
	arpReplyPacket.setTargetProtocolAddress(arpPacket.getSenderProtocolAddress());

	ether.setPayload(arpReplyPacket);
	
	return ether;

    }

    public Ethernet genArpRequest(Ethernet etherPacket, Iface outIface) {
	IPv4 ipv4Packet = (IPv4) etherPacket.getPayload();

	byte[] broadcast = { (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff };
	byte[] targHWAdd = {0,0,0,0,0,0};

	Ethernet ether = new Ethernet();
	ARP arpRequestPacket = new ARP();

	ether.setEtherType(Ethernet.TYPE_ARP);
	ether.setSourceMACAddress(outIface.getMacAddress().toBytes());
	ether.setDestinationMACAddress(broadcast);

	arpRequestPacket.setHardwareType(ARP.HW_TYPE_ETHERNET);
	arpRequestPacket.setProtocolType(ARP.PROTO_TYPE_IP);

	arpRequestPacket.setHardwareAddressLength((byte)(Ethernet.DATALAYER_ADDRESS_LENGTH & 0xff));
	arpRequestPacket.setProtocolAddressLength((byte)4);

	arpRequestPacket.setOpCode(ARP.OP_REQUEST);
	arpRequestPacket.setSenderHardwareAddress(outIface.getMacAddress().toBytes());
	arpRequestPacket.setTargetHardwareAddress(targHWAdd);

	int nextHopIP;
	RouteEntry routeEntry = routeTable.lookup(ipv4Packet.getDestinationAddress());
	if(routeEntry.getGatewayAddress() == 0) {
	    nextHopIP = ipv4Packet.getDestinationAddress();
	}
	else {
	    nextHopIP = routeEntry.getGatewayAddress();
	}

	arpRequestPacket.setTargetProtocolAddress(nextHopIP);
	ether.setPayload(arpRequestPacket);
	return ether;
    }

    public Ethernet genICMPTimeExceeded(Ethernet etherPacket, Iface inIface, byte[] srcMacAddress) {
	
	IPv4 ipv4Packet = (IPv4)etherPacket.getPayload();

	Ethernet ether = new Ethernet();
	IPv4 ip = new IPv4();
	ICMP icmp = new ICMP();
	Data data = new Data();
	ether.setPayload(ip);
	ip.setPayload(icmp);
	icmp.setPayload(data);
	
	icmp.setIcmpType((byte)11);
	icmp.setIcmpCode((byte)0);
	byte[] ipBytes = ipv4Packet.serialize();
	int numIPBytes = ipv4Packet.getHeaderLength()*4 + 8;
	System.out.println("\n\n IP header length: " + numIPBytes + "\n\n");

	byte[] icmpData = new byte[4 + numIPBytes];
	for(int i = 0; i < numIPBytes; i++) {
	    icmpData[i+4] = ipBytes[i];
	}
	data.setData(icmpData);

	ip.setTtl((byte)64);
	ip.setProtocol(IPv4.PROTOCOL_ICMP);
	ip.setSourceAddress(inIface.getIpAddress());
	ip.setDestinationAddress(ipv4Packet.getSourceAddress());

	ether.setEtherType(Ethernet.TYPE_IPv4);
	ether.setSourceMACAddress(inIface.getMacAddress().toBytes());
	ether.setDestinationMACAddress(srcMacAddress);
	return ether;

    }

	/**
	 * Handle an Ethernet packet received on a specific interface.
	 * @param etherPacket the Ethernet packet that was received
	 * @param inIface the interface on which the packet was received
	 */
	public void handlePacket(Ethernet etherPacket, Iface inIface)
	{
		System.out.println("*** -> Received packet: " +
                etherPacket.toString().replace("\n", "\n\t"));
		
		/********************************************************************/
		/* TODO: Handle packets                                             */

		byte[] originalSrcMAC = etherPacket.getSourceMACAddress();
		if(etherPacket.getEtherType() == Ethernet.TYPE_ARP) {
		    System.out.println("\nHandling the arp packet...");
		    ARP arpPacket = (ARP)etherPacket.getPayload();
		    int targetIp = ByteBuffer.wrap(arpPacket.getTargetProtocolAddress()).getInt();
		    int senderIp = ByteBuffer.wrap(arpPacket.getSenderProtocolAddress()).getInt();
		    if(targetIp != inIface.getIpAddress()) {
			System.out.println("\nARP packet not for our inIface: " + inIface.toString());
			return;
		    }
		    if(arpPacket.getOpCode() == ARP.OP_REQUEST) {
			System.out.println("\nGot arp request...");
			Ethernet ether = genArpReply(etherPacket, inIface);
			sendPacket(ether, inIface);
		    }
		    else {
			System.out.println("\nGot arp reply...");
			if(arpCache.lookup(senderIp) == null) {
			    ARPRequester requester = activeThreads.get(senderIp);
			    if(requester == null) {
				return;
			    }
			    if(!requester.isDone()) {
				requester.setReply(etherPacket, inIface);
				arpCache.insert(new MACAddress(arpPacket.getSenderHardwareAddress()), senderIp);
			    }
			    activeThreads.remove(senderIp);
			}
		    }
		    return;
		}
		else if(etherPacket.getEtherType() != this.IPV4ETHERTYPE) {
		    return;
		}

		IPv4 ipv4Packet = (IPv4) etherPacket.getPayload();
		if(ipv4Packet.getTtl() == 1) {
		    Ethernet ether = null;
		    if((ether = genICMPTimeExceeded(etherPacket, inIface, originalSrcMAC)) != null) {
			sendPacket(ether, inIface);
		    }
		    return;
		}

		short originalChecksum = ipv4Packet.getChecksum();
		ipv4Packet.setChecksum((short) 0x0000);
		byte[] ipv4Bytes = ipv4Packet.serialize();
		byte b1, b2;
		b1 = (byte) ((originalChecksum >> 8) & 0xff);
		b2 = (byte) (originalChecksum & 0xff);
		
		if(!(b1 == ipv4Bytes[10] && b2 == ipv4Bytes[11])) {
		    return;
		}

		Iterator<Iface> ifaceItr = interfaces.values().iterator();
		Iface tempIface = null;

		while(ifaceItr.hasNext()) {
		    tempIface = ifaceItr.next();
		    if(tempIface.getIpAddress() == ipv4Packet.getDestinationAddress()) {
			Ethernet ether = genICMPTimeExceeded(etherPacket, inIface, originalSrcMAC);
			ICMP icmp = (ICMP)ether.getPayload().getPayload();
			icmp.setIcmpType((byte)3);
			if(ipv4Packet.getProtocol() == IPv4.PROTOCOL_TCP || ipv4Packet.getProtocol() == IPv4.PROTOCOL_UDP) {
			    icmp.setIcmpCode((byte)3);
			    sendPacket(ether, inIface);
			}
			else if(ipv4Packet.getProtocol() == IPv4.PROTOCOL_ICMP) {
			    ICMP icmpEchoReq = (ICMP)ipv4Packet.getPayload();
			    if(icmpEchoReq.getIcmpType() == 8) {
				IPv4 ip = (IPv4) ether.getPayload();
				ip.setSourceAddress(ipv4Packet.getDestinationAddress());
				icmp.setIcmpType((byte)0);
				icmp.setIcmpCode((byte)0);
				icmp.setPayload(icmpEchoReq.getPayload());
				sendPacket(ether, inIface);
			    }
			}
			return;
		    }
		}

		RouteEntry routeEntry = routeTable.lookup(ipv4Packet.getDestinationAddress());
		if(routeEntry == null) {
		    System.out.println("\nThe look up has failed.");
		    Ethernet ether = null;
		    if((ether = genICMPTimeExceeded(etherPacket, inIface, originalSrcMAC)) != null) {
			ICMP icmp = (ICMP) ether.getPayload().getPayload();
			icmp.setIcmpType((byte)3);
			icmp.setIcmpCode((byte)0);
			sendPacket(ether, inIface);
		    }
		    return;
		}

		System.out.println("\nDestination address = " + IPv4.fromIPv4Address(routeEntry.getDestinationAddress()));
		System.out.println("\nMask Address = " + IPv4.fromIPv4Address(routeEntry.getMaskAddress()));
		System.out.println("\nLooking to forward the packet");

		ipv4Packet.setTtl((byte)(ipv4Packet.getTtl()-1));
		ipv4Packet.setChecksum((short)(0x0000));
		ipv4Bytes = ipv4Packet.serialize();
		
		short s1 = (short)((ipv4Bytes[10] << 8) & 0xff00);
		short s2 = (short)(ipv4Bytes[11] & 0x00ff);
		
		ipv4Packet.setChecksum((short)(s1 + s2));
		etherPacket.setPayload(ipv4Packet);
		etherPacket.setSourceMACAddress(routeEntry.getInterface().getMacAddress().toBytes());
		
		ArpEntry arpEntry = null;

		int nextHopIP;
		if(routeEntry.getGatewayAddress() == 0) {
		    arpEntry = arpCache.lookup(ipv4Packet.getDestinationAddress());
		    nextHopIP = ipv4Packet.getDestinationAddress();
		}
		else {
		    arpEntry = arpCache.lookup(routeEntry.getGatewayAddress());
		    nextHopIP = routeEntry.getGatewayAddress();
		}

		if(arpEntry == null) {
		    if(activeThreads.containsKey(nextHopIP) && !activeThreads.get(nextHopIP).isDone()) {
			activeThreads.get(nextHopIP).add(etherPacket, inIface, originalSrcMAC);
		    }
		    else {
			Ethernet etherARPReq = genArpRequest(etherPacket, routeEntry.getInterface());
			ARPRequester r = new ARPRequester(etherARPReq, routeEntry.getInterface(), this);
			r.add(etherPacket, inIface, originalSrcMAC);
			activeThreads.put(nextHopIP, r);
			Thread t = new Thread(r);
			t.start();
		    }
		    return;
		}

		MACAddress nextHopMAC = arpEntry.getMac();
		if(nextHopMAC == null) {
		    return;
		}
		else {
		    etherPacket.setDestinationMACAddress(nextHopMAC.toBytes());
		    sendPacket(etherPacket, routeEntry.getInterface());
		}		
		
		/********************************************************************/
	}
}
