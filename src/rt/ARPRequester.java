package edu.wisc.cs.sdn.vnet.rt;

import java.util.LinkedList;
import java.util.Queue;

import edu.wisc.cs.sdn.vnet.Iface;
import net.floodlightcontroller.packet.*;

public class ARPRequester implements Runnable{
	
	private Ethernet etherARPReq;
	private Iface arpRepIface, arpReqIface;
	private Router rt;
	private boolean done;
	
	private Queue<Ethernet> waiting;
	private Queue<Iface> waitingIfaces;
	private Queue<byte[]> waitingSrcMacs;
	private Ethernet arpReply;

	public ARPRequester(Ethernet etherARPReq, Iface arpReqIface, Router rt) {
		this.etherARPReq = etherARPReq;
		this.arpReqIface = arpReqIface;
		this.rt = rt;
		done = false;		
		waiting = new LinkedList<Ethernet>();
		waitingIfaces = new LinkedList<Iface>();
		waitingSrcMacs = new LinkedList<byte[]>();
	}
	
	public boolean isDone(){
		return done;
	}
	
	public void setReply(Ethernet arpReply, Iface arpRepIface){
		this.arpRepIface = arpRepIface;
		this.arpReply = arpReply;
		done = true;
	}
        
	public void add(Ethernet packet, Iface inIface, byte[] srcMac)
	{
		waiting.add(packet);
		waitingIfaces.add(inIface);
		waitingSrcMacs.add(srcMac);
	}

	
	public void run() {
		int count = 0;
		while(count < 3)
		{
			rt.sendPacket(etherARPReq, arpReqIface);
		        
			try {
				Thread.sleep(1000);
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
			count++;
			if(done)
				break;
		}
		
		done = true;

		if(arpReply != null)
		{
			ARP arp = (ARP) arpReply.getPayload();
			while(!waiting.isEmpty())
			{
				Ethernet etherPacket = waiting.poll();
				etherPacket.setDestinationMACAddress(arp.getSenderHardwareAddress());
				rt.sendPacket(etherPacket, arpRepIface);
			}
		}
		else
		{
			while(!waiting.isEmpty())
			{	        
				Ethernet etherPacket = waiting.poll();
				Iface inIface = waitingIfaces.poll();
				byte[] origSrcMAC = waitingSrcMacs.poll();
			        
				Ethernet etherICMP = rt.genICMPTimeExceeded(etherPacket,inIface, origSrcMAC);
				ICMP icmp = (ICMP) etherICMP.getPayload().getPayload();
				icmp.setIcmpType((byte)3);
				icmp.setIcmpCode((byte)1);
				
				rt.sendPacket(etherICMP, inIface);
			}
		}
		return;
	}
	
}
