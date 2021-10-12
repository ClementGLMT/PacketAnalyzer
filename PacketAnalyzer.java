import java.util.ArrayList;
import java.util.Map;

public class PacketAnalyzer {
    public static void main(String[] args){
        int i;

        PcapReader pcapReader = new PcapReader("icmp_tcp_udp.pcap");

        Map<String, Object> headers = pcapReader.getFileHeaders();

        ArrayList<Packet> packetList = pcapReader.getPacketList();

        System.out.println("File headers\n");
        System.out.println(headers+"\n");

        // For each packet in the file
        for (i=0; i < packetList.size(); i++) {

            System.out.println("\n------------Packet "+(i+1)+"------------");

            String currentPacket = packetList.get(i).getPacketData();

            System.out.println("Packet Data :\n"+currentPacket);
            
            // Trying to recognize Ethernet protocol
            Ethernet eth = ProtocolParser.recognizeEthernet(currentPacket);

            // If Ethernet is recognized
            if(eth.getIsMatched()){

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

                            // Print IPv4 information
                            System.out.println(ipv4);
                            // System.out.println("IPV4 Headers : "+ipv4.getIpv4Headers());

                            // Decapsulation from IPv4
                            currentPacket = currentPacket.substring(eth.getEthernetData().length());
                            System.out.println(currentPacket);

                            // IPv4 Headers gives us the Layer 4 protocol used
                            switch (ipv4.resolveTransportProtocol()) {
                                case "TCP":

                                    break;

                                case "UDP":

                                break;

                                case "ICMP":
                                    
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

                            // Print ARP Information
                            System.out.println(arp);
                            // System.out.println(arp.getArpData());
        
                            // No Decapsulation, no protocol over ARP @todo a verif quand meme
        
                        }

                    default:

                        break;
                }
            }
            

        }
    }
}
