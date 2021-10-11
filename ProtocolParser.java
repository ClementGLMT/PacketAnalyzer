import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ProtocolParser {

    private String packetData;
    
    public ProtocolParser(String packetData){
        this.packetData = packetData;
    }

    public EthernetData recognizeEthernet(){
        String arpPattern = "([0-9a-fA-F]{12})([0-9a-fA-F]{12})(8100[0-9a-fA-F]{4})?(0800|0806|809b|80F3|86DD)";


        Pattern r = Pattern.compile(arpPattern);

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
}
