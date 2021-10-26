import java.util.ArrayList;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

// javac *.java && java PacketAnalyzer

public class PacketAnalyzer {
    public static void main(String[] args){
        int i;
        int arpC = 0, ethC = 0, ipv4C = 0, udpC = 0, icmpC = 0, tcpC = 0, dnsC = 0, ftpC = 0, ftpDataC = 0, dhcpC = 0, httpC = 0;

        int newDnsC = 0;

        PcapReader pcapReader = new PcapReader("tcp.pcap");

        Map<String, Object> headers = pcapReader.getFileHeaders();

        ArrayList<Packet> packetList = pcapReader.getPacketList();

        System.out.println("File headers\n");
        System.out.println(headers+"\n");

        // Ftp Data is global when passive mode is turned on
        FtpData ftpData = new FtpData();

        // For each packet in the file
        for (i=0; i < packetList.size(); i++) {

            // System.out.println("\n------------Packet "+(i+1)+"------------");

            String currentPacket = packetList.get(i).getPacketData();

            // System.out.println("Packet Data :\n"+currentPacket);

            // System.out.println("Network : "+headers.get("network"));

            if(((String) headers.get("network")).equals("0001")){

                 // Trying to recognize Ethernet protocol
                Ethernet eth = ProtocolParser.recognizeEthernet(currentPacket);

                // If Ethernet is recognized
                if(eth.isMatched()){

                    // Updating packet with ethernet information
                    packetList.set(i, packetList.get(i).addEthernet(eth));

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

                            int ipv4headerLength = Integer.parseInt((String.valueOf(currentPacket.charAt(1))) , 16);

                            // Trying to recognize IPv4
                            // @todo gérer les options ipv4
                            IPv4 ipv4 = ProtocolParser.recognizeIPv4(currentPacket, ipv4headerLength);

                            // If IPv4 is recognized
                            if(ipv4.isMatched() && (ipv4.getMoreFragment() != 1) && (ipv4.getIntFragmentOffset() == 0)){

                                // System.out.println("Dont fragment : "+ipv4.getDontFragment());
                                // System.out.println("More fragment : "+ipv4.getMoreFragment());
                                // System.out.println("Offset : "+ipv4.getIntFragmentOffset());

                                // Increments counter 
                                ipv4C ++;
                                // Print IPv4 information
                                System.out.println(ipv4);
                                // System.out.println("IPV4 Headers : "+ipv4.getIpv4Headers());

                                // System.out.println("Payload ipv4 Size : "+ipv4PayloadSize);

                                // Decapsulation from IPv4
                                currentPacket = currentPacket.substring(ipv4.getHeaderLengthBytes()*2);
                                // System.out.println("Depiled packet : "+currentPacket);

                                // IPv4 Headers gives us the Layer 4 protocol used
                                switch (ipv4.resolveTransportProtocol()) {
                                    case "TCP":

                                        // Retrieving TCP header length
                                        int DO = Integer.parseInt((String.valueOf(currentPacket.charAt(24))) , 16);

                                        Tcp tcp = ProtocolParser.recognizeTcp(currentPacket, DO);

                                        if(tcp.isMatched()){

                                            tcpC++;

                                            System.out.println(tcp);

                                            currentPacket = tcp.getPayload();

                                            System.out.println("TCP Payload : "+tcp.getPayload());
                                            // System.out.println("TCP Payload Ascii : \n"+ProtocolParser.hexaToAscii(tcp.getPayload()));

                                            //Ajouter le parsing de http ici

                                            if(ftpData.isMatched()){
                                                if((tcp.getSourcePort() == ftpData.getPort() || tcp.getSourcePort() == ftpData.getPort()) && !tcp.getPayload().equals("")){
                                                    System.out.println(ftpData);

                                                    ftpDataC++;

                                                }
                                            }

                                            String currentPacketAscii = ProtocolParser.hexaToAscii(tcp.getPayload());

                                            HttpRequest httpRequest = ProtocolParser.recognizeHttpRequest(currentPacketAscii);

                                            HttpResponse httpResponse = ProtocolParser.recognizeHttpResponse(currentPacketAscii);

                                            Ftp ftp = ProtocolParser.recognizeFtp(currentPacketAscii);

                                            if(httpRequest.isMatched()){
                                                httpC++;
                                                System.out.println(httpRequest);
                                            }

                                            if(httpResponse.isMatched()){
                                                httpC++;
                                                System.out.println(httpResponse);
                                            }

                                            if(ftp.isMatched()){

                                                if(ftp.getResponseCode() == 227){
                                                    // Regex : "Entering Passive Mode \([0-9]{1,3},[0-9]{1,3},[0-9]{1,3},[0-9]{1,3},([0-9]{1,4}),([0-9]{1,4})\)"
                                                    ftpData = ProtocolParser.getFtpPassiveInfo(currentPacketAscii, ipv4.getDestinationAddress());
                                                }

                                                ftpC++;

                                                System.out.println(ftp);
                                            }
                                        }

                                        break;

                                    case "UDP":

                                        Udp udp = ProtocolParser.recognizeUdp(currentPacket, ipv4.getTotalLength()-ipv4.getHeaderLengthBytes());

                                        if(udp.isMatched()){

                                            udpC++;

                                            System.out.println(udp);
                                            System.out.println("UDP Headers : "+udp.getUdpHeaders());
                                            System.out.println("UDP Data : "+udp.getUdpData());

                                            // Trying to recognize DHCP
                                            Dhcp dhcp = ProtocolParser.recognizeDhcp(udp.getUdpData());

                                            if(dhcp.isMatched()){

                                                dhcpC++;

                                                System.out.println(dhcp);

                                            }

                                            String currentPacketAscii = ProtocolParser.hexaToAscii(udp.getUdpData());

                                            HttpRequest httpRequest = ProtocolParser.recognizeHttpRequest(currentPacketAscii);

                                            HttpResponse httpResponse = ProtocolParser.recognizeHttpResponse(currentPacketAscii);


                                            if(httpRequest.isMatched()){
                                                httpC++;
                                                System.out.println(httpRequest);
                                            }

                                            if(httpResponse.isMatched()){
                                                httpC++;
                                                System.out.println(httpResponse);
                                            }

                                            // System.out.println("UDP Data Ascii :\n"+currentPacketAscii);

                                            String dnsRegex = "^(?:[0-9a-fA-F]{24})([0-9a-fA-F]{2})((?:(?:2d)|(?:3[0-9])|(?:4(?:[1-9]|[a-f]))|(?:5(?:[0-9]|a))|(?:6(?:[1-9]|[a-f]))|(?:7(?:[0-9]|a)))+)";

                                            Pattern r = Pattern.compile(dnsRegex);

                                            Matcher m = r.matcher(udp.getUdpData());
                                    
                                            boolean result = m.find();

                                            if(result){
                                                System.out.println("DNS matched");
                                                System.out.println("Size : "+Integer.parseInt(m.group(1), 16));
                                                System.out.println("Length du bousin : "+m.group(2).length()*2);
                                                if(Integer.parseInt(m.group(1), 16)*2 == m.group(2).length()){
                                                    System.out.println("DNS matched and checked");
                                                    newDnsC++;

                                                }
                                            }

                                            // Trying to recognize DNS
                                            if(udp.getDestPort() == 53 ||  udp.getSourcePort() == 53){

                                                Dns dns = ProtocolParser.recognizeDns(udp.getUdpData());

                                                if(dns.isMatched()){

                                                    dnsC++;
                                                    System.out.println(dns);
                                                }
                                            }

                                        }

                                    break;

                                    case "ICMP":
                                        
                                        Icmp icmp = ProtocolParser.recognizeIcmp(currentPacket);

                                        if(icmp.isMatched()){

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
                            if(arp.isMatched()){

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
        System.out.println("\n\nCounters : \nEthernet : "+ethC+"\nArp : "+arpC+"\nIPv4 : "+ipv4C+"\nUDP : "+udpC+"\nICMP : "+icmpC+"\nTCP : "+tcpC+"\nDNS : "+dnsC+"\nFTP : "+ftpC+"\nFTP-DATA : "+ftpDataC+"\nDHCP : "+dhcpC+"\nHTTP : "+httpC+"\nDNS counter regex : "+newDnsC);
    }
}
