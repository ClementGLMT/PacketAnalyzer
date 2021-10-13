import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.util.Map;


public class ProtocolParser {

    public static Ethernet recognizeEthernet(String packetData){
        String ethPattern = "([0-9a-fA-F]{12})([0-9a-fA-F]{12})(8100[0-9a-fA-F]{4})?([0-9a-fA-F]{4})";

        Pattern r = Pattern.compile(ethPattern);

        Matcher m = r.matcher(packetData);

        boolean result = m.find();

        if(result){
            Ethernet data = new Ethernet(m.group(1), m.group(2), m.group(3), m.group(4), resolveEtherType(m.group(4)), m.group(0));
            return data;
        } else {
            return new Ethernet();
        }
    }

    public static Arp recognizeArp(Map<String, Object> headers, String packetData){
        String arpPattern = "(?:"+headers.get("network")+")(0800|86dd)(?:"+headers.get("networkLength")+")(04|10)(0001|0002)([0-9a-fA-F]{12})([0-9a-fA-F]{8})([0-9a-fA-F]{12})([0-9a-fA-F]{8})";
        
        Pattern r = Pattern.compile(arpPattern);

        Matcher m = r.matcher(packetData);

        boolean result = m.find();

        if(result){
            Arp data = new Arp(m.group(1), resolveEtherType(m.group(1)), m.group(2), m.group(3), m.group(4), ipv4HexaToHuman(m.group(5)), m.group(6), ipv4HexaToHuman(m.group(7)), m.group(0));
            return data;
        } else {
            return new Arp();
        }
    }

    public static IPv4 recognizeIPv4(String packetData){
        String ipv4Pattern = "4([5-9a-fA-F])([0-9a-fA-F]{2})([0-9a-fA-F]{4})([0-9a-fA-F]{4})([0-9a-fA-F]{4})([0-9a-fA-F]{2})([0-9a-fA-F]{2})([0-9a-fA-F]{4})([0-9a-fA-F]{8})([0-9a-fA-F]{8})";

        Pattern r = Pattern.compile(ipv4Pattern);

        Matcher m = r.matcher(packetData);

        boolean result = m.find();

        if(result){
            IPv4 data = new IPv4(Integer.parseInt(m.group(1), 16) , m.group(2), Integer.parseInt(m.group(3), 16) , m.group(4), m.group(5), m.group(5), m.group(6), m.group(7), m.group(8), ipv4HexaToHuman(m.group(9)), ipv4HexaToHuman(m.group(10)), m.group(0));
            return data;
        } else {
            return new IPv4();
        }
    }

    public static Udp recognizeUdp(String packetData, int dataLength){

        String udpHeaders = packetData.substring(0, 16);

        String udpPattern = "([0-9a-fA-F]{4})([0-9a-fA-F]{4})([0-9a-fA-F]{4})([0-9a-fA-F]{4})";

        Pattern r = Pattern.compile(udpPattern);

        Matcher m = r.matcher(udpHeaders);

        boolean result = m.find();

        if(result){

            Udp udp = new Udp(Integer.parseInt(m.group(1), 16), Integer.parseInt(m.group(2), 16), Integer.parseInt(m.group(3), 16), m.group(4), udpHeaders, packetData.substring(16, (Integer.parseInt(m.group(3), 16)-8)*2+16));
            return udp;

        } else {
            return new Udp();
        }
    }

    public static Icmp recognizeIcmp(String packetData){

        String icmpHeaders = packetData.substring(0, 8);

        String icmpPattern = "([0-9a-fA-F]{2})([0-9a-fA-F]{2})([0-9a-fA-F]{4})";

        Pattern r = Pattern.compile(icmpPattern);

        Matcher m = r.matcher(icmpHeaders);

        boolean result = m.find();

        if(result){

            Icmp icmp = new Icmp(Integer.parseInt(m.group(1), 16), Integer.parseInt(m.group(2), 16), m.group(3), packetData.substring(8));
            return icmp;

        } else {
            return new Icmp();
        }

    }

    // public static Tcp recognizeTcp(String packetData){

    //     int DO = Integer.parseInt(packetData.substring(12,15), 16);

    //     System.out.println(DO);

    // }

    public static String ipv4HexaToHuman(String ipv4Hexa){
        int i;
        String ipv4="";
        for(i=0; i < ipv4Hexa.length(); i+=2){
            ipv4 = ipv4 + Integer.parseInt(ipv4Hexa.substring(i, i+2), 16) + ".";
        }
        return ipv4.substring(0, ipv4.length()-1);
    }

    private static String resolveEtherType(String etherType){
        switch (etherType) {
            case "0800":
                return "IPv4";
            case "0806":
                return "ARP";
            case "86dd":
                return "IPv6";
            default:
                return "Unknown";
        }
    }
}
