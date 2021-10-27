import java.util.ArrayList;
import java.util.Arrays;
import java.util.Hashtable;
import java.util.Map;

// javac *.java && java PacketAnalyzer

public class PacketAnalyzer {

    private static int packetCounter;
    private static int arpC = 0, ethC = 0, ipv4C = 0, udpC = 0, icmpC = 0, tcpC = 0, dnsC = 0, ftpC = 0, ftpDataC = 0, dhcpC = 0, httpC = 0;
    private static FtpData ftpData = new FtpData();
    private static Hashtable<String, ArrayList<Packet>> packetsById = new Hashtable<String, ArrayList<Packet>>();
    private static ArrayList<Packet> packetList;
    private static Hashtable<String, Packet> reassembledPackets;

    private static Packet parsePacketProtocols(Map<String, Object> globalHeaders, Packet packet, boolean isReassembled){

        String currentPacket = packet.getPacketData();

        // Trying to recognize Ethernet protocol
        Ethernet eth = ProtocolParser.recognizeEthernet(currentPacket);

        // If Ethernet is recognized
        if(eth.isMatched()){

            // Updating packet with ethernet information
            packet.addEthernet(eth);

            // Increments Counter
            if(!isReassembled){
                ethC++;
            }

            // Decapsulation from Ethernet
            currentPacket = currentPacket.substring(eth.getEthernetData().length());

            // EtherType gives us the layer 3 protocol used
            switch (eth.getetherTypeHuman()) {

                // Case IPv4 as Layer 3 protocol
                case "IPv4":

                    // if(isReassembled)
                    //     currentPacket = packet.getIpv4().getPayload();

                    int ipv4headerLength = Integer.parseInt((String.valueOf(currentPacket.charAt(1))) , 16);

                    // Trying to recognize IPv4
                    // @todo gérer les options ipv4
                    IPv4 ipv4 = ProtocolParser.recognizeIPv4(currentPacket, ipv4headerLength);

                    // If IPv4 is recognized
                    if(ipv4.isMatched()){

                        // Increments counter 
                        if(!isReassembled){
                            ipv4C ++;
                        }
                        // Updating packet with Ipv4 information
                        packet.addIpv4(ipv4);

                        // Decapsulation from IPv4
                        currentPacket = currentPacket.substring(ipv4.getHeaderLengthBytes()*2);
                        ipv4.setPayload(currentPacket);

                        // We don't treat IP fragmentation case here
                        if(((ipv4.getMoreFragment() != 1) && (ipv4.getIntFragmentOffset() == 0)) || isReassembled){
                            // System.out.println("Dont fragment : "+ipv4.getDontFragment());
                            // System.out.println("More fragment : "+ipv4.getMoreFragment());
                            // System.out.println("Offset : "+ipv4.getIntFragmentOffset());

                            // System.out.println("Depiled packet : "+currentPacket);

                            // IPv4 Headers gives us the Layer 4 protocol used
                            switch (ipv4.resolveTransportProtocol()) {
                                case "TCP":

                                    // Retrieving TCP header length
                                    int DO = Integer.parseInt((String.valueOf(currentPacket.charAt(24))) , 16);

                                    Tcp tcp = ProtocolParser.recognizeTcp(currentPacket, DO);

                                    if(tcp.isMatched()){

                                        tcpC++;

                                        // Update packet with TCP information
                                        packet.addTcp(tcp);

                                        currentPacket = tcp.getPayload();

                                        if(ftpData.isMatched()){
                                            if((tcp.getSourcePort() == ftpData.getPort() || tcp.getSourcePort() == ftpData.getPort()) && !tcp.getPayload().equals("")){
                                                
                                                // Update packet with FtpData information
                                                packet.addFtpData(ftpData);
                                                ftpDataC++;

                                            }
                                        }

                                        String currentPacketAscii = ProtocolParser.hexaToAscii(tcp.getPayload());

                                        // Try to match applicative protocols
                                        HttpRequest httpRequest = ProtocolParser.recognizeHttpRequest(currentPacketAscii);

                                        HttpResponse httpResponse = ProtocolParser.recognizeHttpResponse(currentPacketAscii);

                                        Ftp ftp = ProtocolParser.recognizeFtp(currentPacketAscii);

                                        if(httpRequest.isMatched()){
                                            
                                            httpC++;

                                            packet.addHttpRequest(httpRequest);
                                            // System.out.println(httpRequest);
                                        }

                                        if(httpResponse.isMatched()){

                                            httpC++;
                                            
                                            packet.addHttpResponse(httpResponse);
                                            // System.out.println(httpResponse);
                                        }

                                        if(ftp.isMatched()){

                                            // If Ftp is entering passive mode
                                            if(ftp.getResponseCode() == 227){
                                                // Regex : "Entering Passive Mode \([0-9]{1,3},[0-9]{1,3},[0-9]{1,3},[0-9]{1,3},([0-9]{1,4}),([0-9]{1,4})\)"
                                                ftpData = ProtocolParser.getFtpPassiveInfo(currentPacketAscii, ipv4.getDestinationAddress());
                                            }

                                            ftpC++;
  
                                            packet.addFtp(ftp);
                                        }
                                    }

                                    break;

                                case "UDP":

                                    Udp udp = ProtocolParser.recognizeUdp(currentPacket, ipv4.getTotalLength()-ipv4.getHeaderLengthBytes());

                                    if(udp.isMatched()){
                                          
                                        udpC++;
                                        // System.out.println(udp);
                                        // System.out.println("UDP Headers : "+udp.getUdpHeaders());
                                        // System.out.println("UDP Data : "+udp.getUdpData());

                                        packet.addUdp(udp);

                                        // Trying to recognize DHCP
                                        Dhcp dhcp = ProtocolParser.recognizeDhcp(udp.getUdpData());

                                        if(dhcp.isMatched()){
                                            
                                            dhcpC++;
  
                                            packet.addDhcp(dhcp);

                                        }

                                        String currentPacketAscii = ProtocolParser.hexaToAscii(udp.getUdpData());

                                        HttpRequest httpRequest = ProtocolParser.recognizeHttpRequest(currentPacketAscii);

                                        HttpResponse httpResponse = ProtocolParser.recognizeHttpResponse(currentPacketAscii);

                                        if(httpRequest.isMatched()){
                                            
                                            httpC++;
                                             packet.addHttpRequest(httpRequest);
                                            // System.out.println(httpRequest);
                                        }

                                        if(httpResponse.isMatched()){

                                            httpC++;
                                             packet.addHttpResponse(httpResponse);
                                            // System.out.println(httpResponse);
                                        }

                                        // System.out.println("UDP Data Ascii :\n"+currentPacketAscii);

                                        // Trying to recognize DNS
                                        if(udp.getDestPort() == 53 ||  udp.getSourcePort() == 53){

                                                // packetList.set(i, packetList.get(i).addDebug("Matched on : "+udp.getUdpData()));
                                                // packetList.set(i, packetList.get(i).addDebug("Size : "+Integer.parseInt(m.group(1), 16)*2));
                                                // packetList.set(i, packetList.get(i).addDebug("Length du bousin : "+m.group(2).length()));

                                                // System.out.println("DNS matched");
                                                // System.out.println("Size : "+Integer.parseInt(m.group(1), 16));
                                                // System.out.println("Length du bousin : "+m.group(2).length());
                                                    // System.out.println("DNS matched and checked");

                                            Dns dns = ProtocolParser.recognizeDns(udp.getUdpData());

                                            if(dns.isMatched()){
                                                
                                                dnsC++;
                                                packet.addDns(dns);
                                                // System.out.println(dns); 
                                            }
                                        }

                                    }

                                    break;

                                case "ICMP":
                                    
                                    Icmp icmp = ProtocolParser.recognizeIcmp(currentPacket);

                                    if(icmp.isMatched()){

                                        icmpC++;
                                        packet.addIcmp(icmp);

                                        // System.out.println(icmp);

                                    }

                                    break;
                            
                                default:
                                    break;
                            }
                        } else {

                        }

                    }


                    break;

                // Case ARP over Ethernet
                case "ARP":

                    // Trying to recognize ARP
                    Arp arp = ProtocolParser.recognizeArp(globalHeaders, currentPacket);

                    // If ARP is recognized
                    if(arp.isMatched()){

                        // Increments Counter
                        arpC++;

                        packet.addArp(arp);

                        // Print ARP Information
                        // System.out.println(arp);
                        // System.out.println(arp.getArpData());
    
                        // No Decapsulation, no protocol over ARP @todo a verif quand meme
    
                    }

                    break;

                default:

                    break;
            }
        }

        return packet;

    }

    private static Packet reassemblPacket(ArrayList<Packet> packets){
        // ArrayList<Packet> packets = packetsTmp;
        // int intialSize = packets.size();
        Packet reassembled = new Packet();
        int currentOffset = 0;
        int i=0;
        for (Packet p: packets){
            if(p.getIpv4().getFragmentOffsetBytes()*8 == 0 && p.getIpv4().getMoreFragment() == 1){
                reassembled = new Packet(p);
                // System.out.println("Packet 2655 Ipv4 payload après dans chelou 2: \n"+packetList.get(2654).getIpv4().getPayload());

                // System.out.println("Initialized with payload :\n"+reassembled.getIpv4().getPayload());
                currentOffset += p.getIpv4().getPayloadLength();
                packets.remove(i);
            }
            i++;
        }


        // System.out.println("Current offset after initialization : "+currentOffset);
        // System.out.println("Initalized packet id : "+reassembled.getIpv4().getIdentification());

        // If the precedent if statement didn't match, currentOffset will be equal to 0
        // In this case, it's a coincidence that the 2 packets have the same ID
        if(currentOffset != 0){
            i=0;
            int todelete=0;
            while(packets.size() != 0){
                for(Packet p: packets){
                    // System.out.println("Offset testing : "+p.getIpv4().getFragmentOffsetBytes());
                    // System.out.println("Packet id testing : "+p.getIpv4().getIdentification());

                    if(p.getIpv4().getFragmentOffsetBytes() == currentOffset){

                        reassembled.setPacketData(reassembled.getPacketData()+ p.getIpv4().getPayload());

                        reassembled.getIpv4().setPayload(reassembled.getIpv4().getPayload() + p.getIpv4().getPayload());
                        // System.out.println("Packet 2655 Ipv4 payload dans appel chelou : \n"+packetList.get(2654).getIpv4().getPayload());

                        // System.out.println("New reassembled payload :\n"+reassembled.getIpv4().getPayload());
                        currentOffset += p.getIpv4().getPayloadLength();
                        todelete = i;
                        break;
                    }
                    i++;
                }
                packets.remove(todelete);
            }
        }
        // System.out.println("Returning payload :\n"+reassembled.getIpv4().getPayload());
        return reassembled;
    }

    private static boolean parseFilter(String arg, Packet p){

        if(p == null){
            return false;
        }

        switch(arg.toLowerCase()){
            case "eth":
                return p.getEth().isMatched();

            case "arp":
                return p.getArp().isMatched();

            case "ip":
                return p.getIpv4().isMatched();

            case "tcp":
                return p.getTcp().isMatched();

            case "udp":
                return p.getUdp().isMatched();

            case "icmp":
                return p.getIcmp().isMatched();

            case "dhcp":
                return p.getDhcp().isMatched();

            case "ftp":
                return p.getFtp().isMatched() || p.getFtpData().isMatched();

            case "dns":
                return p.getDns().isMatched();

            case "http":
                return p.getHttpRequest().isMatched() || p.getHttpResponse().isMatched();

            default:
                return true;
        }
    }

    private static Packet checkForReassembled(Packet p){
        return reassembledPackets.get(p.getIpv4().getIdentification());
    }

    public static void main(String[] args){

        PcapReader pcapReader = new PcapReader(args[0]);

        Map<String, Object> globalHeaders = pcapReader.getFileHeaders();

        packetList = pcapReader.getPacketList();

        reassembledPackets = new Hashtable<String, Packet>();

        System.out.println("File headers\n");
        System.out.println(globalHeaders+"\n");


        if(((String) globalHeaders.get("network")).equals("0001")){
            
            // For each packet in the file, parse its data
            for (packetCounter=0; packetCounter < packetList.size(); packetCounter++) {


                Packet packet = parsePacketProtocols(globalHeaders, packetList.get(packetCounter), false);


                if(packet.getIpv4().isMatched() /*&& !packet.getIpv4().getIdentification().equals("0000")*/){
                    if(packetsById.putIfAbsent(packet.getIpv4().getIdentification(), new ArrayList<Packet>(Arrays.asList(new Packet[] {new Packet(packet)}))) != null){

                        // System.out.println("Testing timestamps for packet "+(packetCounter+1));
                        int current = (Integer) packet.getPacketHeaders().get("ts_sec");
                        int fromHT = (Integer) packetsById.get(packet.getIpv4().getIdentification()).get(0).getPacketHeaders().get("ts_sec");
                        // System.out.println("Current : "+current);
                        // System.out.println("From hashtable : "+fromHT);
                        // System.out.println("Equality test : "+ (current == fromHT));

                        // If the packet has the same timestamp, we consider that it's not a coincidence that the packets has the same IP id.
                        if(current == fromHT){
                            ArrayList<Packet> tmp = packetsById.get(packet.getIpv4().getIdentification());
                            tmp.add(new Packet(packet));
                            packetsById.put(packet.getIpv4().getIdentification(), tmp);
                        }
                    }
                }

                // if(2653 <= packetCounter && packetCounter <= 2656)
                    // System.out.println("Setting packet "+(packetCounter+1)+"\nIpv4 payload : "+packet.getIpv4().getPayload());
                packetList.set(packetCounter, packet);

            }
        } else {
            System.out.println("Capture not from an Ethernet Data-Link capture, exiting");
        }

        // System.out.println("Packet 2655 Ipv4 payload before reassembling : \n"+packetList.get(2654).getIpv4().getPayload());
        // System.out.println("Packet 2656 Ipv4 payload before reassembling : \n"+packetList.get(2655).getIpv4().getPayload());

        int count = 1;
        for (Map.Entry<String, ArrayList<Packet>> e : packetsById.entrySet()){
            if(e.getValue().size() > 1){

                Packet reassembledPacket = reassemblPacket((ArrayList<Packet>) e.getValue().clone());

                if(!reassembledPacket.getPacketData().equals("")){

                    reassembledPacket = parsePacketProtocols(globalHeaders, reassembledPacket, true);

                    reassembledPackets.put(reassembledPacket.getIpv4().getIdentification(), reassembledPacket);


                } else {
                    // System.out.println("Onéla");
                }
            }
            count++;
        }

        packetCounter=1;
        int fragmentedCursor = 0;
        int printCounter = 0;
        ArrayList<Integer> fragmentedIndexes = new ArrayList<Integer>();
        for (Packet packet: packetList) {

            Packet rea = checkForReassembled(packet);

            if(parseFilter(args[1], packet) || parseFilter(args[1], rea)){

                System.out.println("\n\n------------Packet "+packetCounter+"------------");
                // System.out.println("IPv4 Payload of current : "+packet.getIpv4().getPayload());
                ArrayList<Packet> frags = packetsById.get(packet.getIpv4().getIdentification());
                // System.out.println("Frags size for id "+packet.getIpv4().getIdentification()+" : "+frags.size());
                if(frags != null && frags.size() > 1){
                    System.out.println("\n------Fragmented IP Packet "+(fragmentedCursor+1)+" of "+frags.size()+"------");
                    fragmentedCursor++;
                }
                System.out.println(packet);

                if(frags != null && fragmentedCursor == frags.size() && fragmentedCursor != 0){
                    System.out.println("\n------Reassembled IP Packet from packet "+(packetCounter-frags.size()+1)+" to packet "+packetCounter+"------");
                    System.out.println(rea);
                    fragmentedIndexes.add(packetCounter);
                    fragmentedCursor = 0;
                }

                if(packet.hasDebug()){
                    System.out.println("\n------DEBUG------");
                    packet.printDebug();
                }
                printCounter++;
            // Afficher au bon moment le paquet réassemblé
            }
            packetCounter++;
        }

        System.out.println("\n\n------------SUMMARY------------");

        System.out.println(""+printCounter+" packets displayed from "+args[0]+" with filter \""+args[1]+"\"\n");

        if(!fragmentedIndexes.isEmpty()){
            System.out.println("\n\n"+fragmentedIndexes.size()+" Packets reassembled from IP fragmentation, see them at :");
            for (Integer i: fragmentedIndexes){
                System.out.println("\tPacket "+i);
            }
        }
        System.out.println("\n\nCounters : \nEthernet : "+ethC+"\nArp : "+arpC+"\nIPv4 : "+ipv4C+"\nUDP : "+udpC+"\nICMP : "+icmpC+"\nTCP : "+tcpC+"\nDNS : "+dnsC+"\nFTP : "+ftpC+"\nFTP-DATA : "+ftpDataC+"\nDHCP : "+dhcpC+"\nHTTP : "+httpC);

    }
}
