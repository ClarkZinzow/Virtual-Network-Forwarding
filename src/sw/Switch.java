package edu.wisc.cs.sdn.vnet.sw;

import net.floodlightcontroller.packet.Ethernet;
import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

import java.util.Collection;
import java.util.Map;
import java.util.Iterator;
import java.util.concurrent.ConcurrentHashMap;
import net.floodlightcontroller.packet.MACAddress;

/**
 * @author Aaron Gember-Jacobson
 */
public class Switch extends Device implements Runnable
{	
    private ConcurrentHashMap<MACAddress, Iface> forwardingTable;
    private ConcurrentHashMap<MACAddress, Long> ftableTime;
    private Collection<Iface> iFaces;
    private Iterator<Iface> itr;
    private Long currTime;
    private Thread flushThread;
    private final long TIMEOUT;
	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */
	public Switch(String host, DumpFile logfile)
	{
		super(host,logfile);
		TIMEOUT = 15000000000L;
		forwardingTable = new ConcurrentHashMap<MACAddress, Iface>();
		ftableTime = new ConcurrentHashMap<MACAddress, Long>();
		flushThread = new Thread(this, "ForwardingTableFlush");
		flushThread.start();
	}

	/**
	 * Handle an Ethernet packet received on a specific interface.
	 * @param etherPacket the Ethernet packet that was received
	 * @param inIface the interface on which the packet was received
	 */
	public void handlePacket(Ethernet etherPacket, Iface inIface)
	{
	    currTime = System.nanoTime();
		System.out.println("*** -> Received packet: " +
                etherPacket.toString().replace("\n", "\n\t"));
		
		/********************************************************************/
		/* TODO: Handle packets                                             */
		
		/********************************************************************/
		MACAddress smac = etherPacket.getSourceMAC();
		MACAddress dmac = etherPacket.getDestinationMAC();
		Iface outIface = null;
		if(ftableTime.containsKey(dmac)) {
		    outIface = forwardingTable.get(dmac);
		}
		if(outIface == null) {
		    System.out.println("Broadcast\n");
		    iFaces = interfaces.values();
		    itr = iFaces.iterator();
		    Iface iface;
		    while(itr.hasNext()) {
			iface = itr.next();
			if(iface != inIface) {
			    sendPacket(etherPacket, iface);
			}
		    }
		}
		else {
		    sendPacket(etherPacket, outIface);
		    System.out.println("Sent to iface: " + outIface.toString() + " at " + System.currentTimeMillis() + "\n");
		}
		if(!forwardingTable.containsKey(smac)) {
		    forwardingTable.put(smac, inIface);
		    ftableTime.put(smac, currTime);
		}
		else {
		    ftableTime.remove(smac);
		    ftableTime.put(smac, currTime);
		}
	}

    public void start() {
	if(flushThread == null) {
	    flushThread = new Thread(this, "ForwardingTableFlush");
	    flushThread.start();
	}
    }

    public void run() {
	Long ttime;
	try {
	    while(true) {
		Thread.sleep(1000);
		ttime = System.nanoTime();
		for(Map.Entry<MACAddress, Long> entry : ftableTime.entrySet()) {
		    if(ttime - entry.getValue() > TIMEOUT) {
			MACAddress tmac = entry.getKey();
			ftableTime.remove(tmac);
			forwardingTable.remove(tmac);
		    }
		}
	    }
	}
	catch(InterruptedException e) {
	    System.out.println("Interrupted exception caught: " + e);
	}
    }
}
