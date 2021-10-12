import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.Map;


public class ProtocolParser {

    private String packetData;
    
    public ProtocolParser(String packetData){
        this.packetData = packetData;
    }

    public EthernetData recognizeEthernet(){
        String ethPattern = "([0-9a-fA-F]{12})([0-9a-fA-F]{12})(8100[0-9a-fA-F]{4})?(0800|0806|86DD)";

        Pattern r = Pattern.compile(ethPattern);

        Matcher m = r.matcher(packetData);

        boolean result = m.find();

        if(result){
            EthernetData data = new EthernetData(m.group(1), m.group(2), m.group(3), m.group(4), resolveEtherType(m.group(4)));
            return data;
        } else {
            return new EthernetData();
        }
    }

    private String resolveEtherType(String etherType){
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

    public ArpData recognizeArp(Map<String, Object> headers){
        String arpPattern = "(?:"+headers.get("network")+")(0800|86DD)(?:"+headers.get("networkLength")+")(04|10)(0001|0002)([0-9a-fA-F]{12})([0-9a-fA-F]{8})([0-9a-fA-F]{12})([0-9a-fA-F]{8})";
        
        Pattern r = Pattern.compile(arpPattern);

        Matcher m = r.matcher(packetData);

        boolean result = m.find();

        if(result){
            ArpData data = new ArpData(m.group(1), resolveEtherType(m.group(1)), m.group(2), m.group(3), m.group(4), ipv4HexaToHuman(m.group(5)), m.group(6), ipv4HexaToHuman(m.group(7)));
            return data;
        } else {
            return new ArpData();
        }
    }

    // public recognizeIPv4()

    public static String ipv4HexaToHuman(String ipv4Hexa){
        int i;
        String ipv4="";
        for(i=0; i < ipv4Hexa.length(); i+=2){
            ipv4 = ipv4 + Integer.parseInt(ipv4Hexa.substring(i, i+2), 16) + ".";
        }
        return ipv4.substring(0, ipv4.length()-1);
    }
}
