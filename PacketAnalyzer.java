import java.util.ArrayList;
import java.util.Map;

// javac PacketAnalyzer.java PcapReader.java ProtocolParser.java Packet.java Ethernet.java Arp.java IPv4.java && java PacketAnalyzer

public class PacketAnalyzer {
    public static void main(String[] args){
        int i;
        int arpC = 0, ethC = 0, ipv4C = 0, udpC = 0, icmpC = 0;

        PcapReader pcapReader = new PcapReader("tcp.pcap");

        Map<String, Object> headers = pcapReader.getFileHeaders();

        ArrayList<Packet> packetList = pcapReader.getPacketList();

        System.out.println("File headers\n");
        System.out.println(headers+"\n");

        // For each packet in the file
        for (i=0; i < packetList.size(); i++) {

            System.out.println("\n------------Packet "+(i+1)+"------------");

            String currentPacket = packetList.get(i).getPacketData();

            System.out.println("Packet Data :\n"+currentPacket);

            System.out.println("Network : "+headers.get("network"));

            if(((String) headers.get("network")).equals("0001")){

                 // Trying to recognize Ethernet protocol
                Ethernet eth = ProtocolParser.recognizeEthernet(currentPacket);

                // If Ethernet is recognized
                if(eth.getIsMatched()){

                    // Increments Counter
                    ethC++;

                    // Print Ethernet information
                    System.out.println(eth);
                    // System.out.println(eth.getEthernetData());

                    // Decapsulation from Ethernet
                    currentPacket = currentPacket.substring(eth.getEthernetData().length());

                    // EtherType gives us the layer 3 protocol used
                    switch (eth.getetherTypeHuman()) {

                        // Case IPv4 as Layer 3 protocol
                        case "IPv4":

                            // Trying to recognize IPv4
                            IPv4 ipv4 = ProtocolParser.recognizeIPv4(currentPacket);

                            // If IPv4 is recognized
                            if(ipv4.getIsMatched()){

                                // Increments counter 
                                ipv4C ++;
                                // Print IPv4 information
                                System.out.println(ipv4);
                                // System.out.println("IPV4 Headers : "+ipv4.getIpv4Headers());

                                int ipv4PayloadSize = ipv4.getTotalLength()-(ipv4.getHeaderLengthBytes());

                                System.out.println("Payload ipv4 Size : "+ipv4PayloadSize);

                                // Decapsulation from IPv4
                                currentPacket = currentPacket.substring(ipv4.getIpv4Headers().length());
                                System.out.println("Depiled packet : "+currentPacket);

                                // IPv4 Headers gives us the Layer 4 protocol used
                                switch (ipv4.resolveTransportProtocol()) {
                                    case "TCP":

                                        // Tcp tcp = ProtocolParser.recognizeTcp(currentPacket);
                                        int DO = Integer.parseInt((String.valueOf(currentPacket.charAt(24))) , 16);

                                        System.out.println("TCP Header Length String: "+currentPacket.charAt(12));

                                        System.out.println("TCP Header Length : "+DO);

                                        break;

                                    case "UDP":

                                        Udp udp = ProtocolParser.recognizeUdp(currentPacket, ipv4.getTotalLength()-ipv4.getHeaderLengthBytes());

                                        if(udp.getIsMatched()){

                                            udpC++;

                                            System.out.println(udp);
                                            System.out.println("UDP Headers : "+udp.getUdpHeaders());
                                            System.out.println("UDP Data : "+udp.getUdpData());

                                        }

                                    break;

                                    case "ICMP":
                                        
                                        Icmp icmp = ProtocolParser.recognizeIcmp(currentPacket);

                                        if(icmp.getIsMatched()){

                                            icmpC++;

                                            System.out.println(icmp);

                                        }

                                        break;
                                
                                    default:
                                        break;
                                }
                            }

                            break;

                        // Case ARP over Ethernet
                        case "ARP":

                            // Trying to recognize ARP
                            Arp arp = ProtocolParser.recognizeArp(headers, currentPacket);

                            // If ARP is recognized
                            if(arp.getIsMatched()){

                                // Increments Counter
                                arpC++;

                                // Print ARP Information
                                System.out.println(arp);
                                // System.out.println(arp.getArpData());
            
                                // No Decapsulation, no protocol over ARP @todo a verif quand meme
            
                            }

                        default:

                            break;
                    }
                }
            } else {
                System.out.println("Capture not from an Ethernet Data-Link capture, exiting");
            }
        }
        System.out.println("\n\nCounters : \nEthernet : "+ethC+"\nArp : "+arpC+"\nIPv4 : "+ipv4C+"\nUDP : "+udpC+"\nICMP : "+icmpC);
    }
}
