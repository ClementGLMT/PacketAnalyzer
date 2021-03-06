package src;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
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

    public static IPv4 recognizeIPv4(String packetData, int length){
        String ipv4Pattern = "4([5-9a-fA-F])([0-9a-fA-F]{2})([0-9a-fA-F]{4})([0-9a-fA-F]{4})([0-9a-fA-F]{4})([0-9a-fA-F]{2})([0-9a-fA-F]{2})([0-9a-fA-F]{4})([0-9a-fA-F]{8})([0-9a-fA-F]{8})([0-9a-fA-F]{0,40})";

        String ipv4Headers = packetData.substring(0, length*8);

        Pattern r = Pattern.compile(ipv4Pattern);

        Matcher m = r.matcher(ipv4Headers);

        boolean result = m.find();

        if(result){
            IPv4 data = new IPv4(Integer.parseInt(m.group(1), 16) , m.group(2), Integer.parseInt(m.group(3), 16) , m.group(4), m.group(5), m.group(5), m.group(6), m.group(7), m.group(8), ipv4HexaToHuman(m.group(9)), ipv4HexaToHuman(m.group(10)), m.group(11), m.group(0));
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

    public static Tcp recognizeTcp(String packetData, int DO){

        String tcpHeaders = packetData.substring(0, DO*8);

        String tcpPattern = "([0-9a-fA-F]{4})([0-9a-fA-F]{4})([0-9a-fA-F]{8})([0-9a-fA-F]{8})(?:[0-9a-fA-F]{1})0([0-9a-fA-F]{2})([0-9a-fA-F]{4})([0-9a-fA-F]{4})([0-9a-fA-F]{4})([0-9a-fA-F]{0,40})";

        Pattern r = Pattern.compile(tcpPattern);

        Matcher m = r.matcher(tcpHeaders);

        boolean result = m.find();

        if(result){

            Tcp tcp = new Tcp(Integer.parseInt(m.group(1), 16), Integer.parseInt(m.group(2), 16), Long.parseLong(m.group(3), 16), Long.parseLong(m.group(4), 16), DO, m.group(5), m.group(6), m.group(7), m.group(8), m.group(9), packetData.substring(DO*8), tcpHeaders);
            return tcp;

        } else {
            return new Tcp();
        }
    }

    public static Dns recognizeDns(String packetData){


        String dnsRegex = "^(?:[0-9a-fA-F]{24})([0-9a-fA-F]{2})((?:(?:2d)|(?:3[0-9])|(?:4(?:[1-9]|[a-f]))|(?:5(?:[0-9]|a))|(?:6(?:[1-9]|[a-f]))|(?:7(?:[0-9]|a)))+)";

        Pattern r = Pattern.compile(dnsRegex);

        Matcher m = r.matcher(packetData);

        boolean result = m.find();

        if(result){

            // If we really have DNS (check on the size given and the name that follows)
            if(Integer.parseInt(m.group(1), 16)*2 == m.group(2).length()){

                String dnsHeaders = packetData.substring(0, 24);
        
                String dnsData = packetData.substring(24);

                String dnsPattern = "([0-9a-fA-F]{4})([0-9a-fA-F]{4})([0-9a-fA-F]{4})([0-9a-fA-F]{4})([0-9a-fA-F]{4})([0-9a-fA-F]{4})";
                
                r = Pattern.compile(dnsPattern);

                m = r.matcher(dnsHeaders);

                result = m.find();

                if(result){

                    Dns dns = new Dns(m.group(1), Integer.parseInt(m.group(2), 16), m.group(3), m.group(4), m.group(5), m.group(6), dnsData);
                    return dns;

                } else {
                    return new Dns();
                }
            } else {
                return new Dns();
            }
            
        } else {
            return new Dns();
        }

    }

    public static Ftp recognizeFtp(String packetDataAscii){

        // Building regex for matching a command
        String ftpCommands = "";
        for (FtpCommands ftpcom : java.util.Arrays.asList(FtpCommands.values())) {
            ftpCommands += ftpcom.toString()+"|";
        }
        String ftpPattern = "^("+ftpCommands.substring(0, ftpCommands.length()-1)+") ?([ -~]*)?\r\n";

        // Building a regex for matching a response
        String ftpReplyCodes = "";
        for (FtpResponseCodes ftpresp : java.util.Arrays.asList(FtpResponseCodes.values())) {
            ftpReplyCodes += ftpresp.toString()+"|";
        }
        String ftpRespondeCodesPattern = "^(("+ftpReplyCodes.substring(0, ftpReplyCodes.length()-1)+")[- ]?)([ -~]*)\r\n";

        // Trying to match a command
        Pattern r = Pattern.compile(ftpPattern);       
        Matcher m = r.matcher(packetDataAscii);
        boolean result = m.find();

        // If a command is matched
        if(result){
            Ftp ftpCom = new Ftp(m.group(1), m.group(2), 0);
            return ftpCom;
        } else {
                       
            // Trying to match response
            r = Pattern.compile(ftpRespondeCodesPattern);
            m = r.matcher(packetDataAscii);
            result = m.find();

            if(result){

                Ftp ftpResp = new Ftp("", m.group(3),Integer.parseInt(m.group(1).substring(0, m.group(1).length()-1)));
                return ftpResp;
            }
        }
        return new Ftp();

    }

    public static FtpData getFtpPassiveInfo(String ftpArgs, String ipClient){
        String ftpPassive = "Entering Passive Mode "+"\\("+"([0-9]{1,3}),([0-9]{1,3}),([0-9]{1,3}),([0-9]{1,3}),([0-9]{1,4}),([0-9]{1,4})\\)";
        
        Pattern r = Pattern.compile(ftpPassive);

        Matcher m = r.matcher(ftpArgs);

        boolean result = m.find();

        if(result){
            FtpData ftpData = new FtpData(m.group(1)+"."+m.group(2)+"."+m.group(3)+"."+m.group(4), Integer.parseInt(m.group(5))*256 + Integer.parseInt(m.group(6)), ipClient);
            return ftpData;
        } else {
            return new FtpData();
        }
    }

    public static Dhcp recognizeDhcp(String packetData){

        String dhcpPattern = "^0([12])01([0-9a-fA-F]{2})([0-9a-fA-F]{2})([0-9a-fA-F]{8})([0-9a-fA-F]{4})([0-9a-fA-F]{4})([0-9a-fA-F]{8})([0-9a-fA-F]{8})([0-9a-fA-F]{8})([0-9a-fA-F]{8})([0-9a-fA-F]{32})([0-9a-fA-F]{128})([0-9a-fA-F]{256})63825363([0-9a-fA-F]*)?";

        Pattern r = Pattern.compile(dhcpPattern);

        Matcher m = r.matcher(packetData);

        boolean result = m.find();

        if(result){
            Dhcp dhcp = new Dhcp(Integer.parseInt(m.group(1), 16), 1, Integer.parseInt(m.group(2), 16), Integer.parseInt(m.group(3), 16), m.group(4), Integer.parseInt(m.group(5), 16), m.group(6), ipv4HexaToHuman(m.group(7)), ipv4HexaToHuman(m.group(8)), ipv4HexaToHuman(m.group(9)), ipv4HexaToHuman(m.group(10)), m.group(11), m.group(12), m.group(13), m.group(14));
            return dhcp;
        } else {
            return new Dhcp();
        }
    }

    public static HttpRequest recognizeHttpRequest(String packetDataAscii){

        String http09and10Regex = "^(GET|OPTIONS|HEAD|POST|PUT|DELETE|TRACE|CONNECT) (((https?|http|ftp|file)://[-a-zA-Z0-9+&@#/%?=~_|!:,.;]*[-a-zA-Z0-9+&@#/%=~_|])|(/[-a-zA-Z0-9+&@#/%?=~_|!:,.;]*[-a-zA-Z0-9+&@#/%=~_|])|(/)) HTTP/(?:[01]\\.[09])";
        String http11Regex = "^(GET|OPTIONS|HEAD|POST|PUT|DELETE|TRACE|CONNECT) (((https?|http|ftp|file)://[-a-zA-Z0-9+&@#/%?=~_|!:,.;]*[-a-zA-Z0-9+&@#/%=~_|])|(/[-a-zA-Z0-9+&@#/%?=~_|!:,.;]*[-a-zA-Z0-9+&@#/%=~_|])|(/)) HTTP/1\\.1\\r\\n([\\x20-\\x7E].*:[\\x20-\\x7E].*\\r\\n)*[hH][oO][sS][tT]:";

        Pattern r = Pattern.compile(http11Regex);

        Matcher m = r.matcher(packetDataAscii);

        boolean result = m.find();

        if(result){

            HttpRequest http = new HttpRequest(m.group(1), m.group(2), packetDataAscii.substring(packetDataAscii.indexOf("\n")+1));
            return http;

        } else {
            r = Pattern.compile(http09and10Regex);

            m = r.matcher(packetDataAscii);
    
            result = m.find();

            if(result){
                HttpRequest http = new HttpRequest(m.group(1), m.group(2), packetDataAscii.substring(packetDataAscii.indexOf("\n")+1));
                return http;
            } else {
                return new HttpRequest();
            }
        }
    }

    public static HttpResponse recognizeHttpResponse(String packetDataAscii){

        String httpResponsePattern = "^HTTP/[10].[019] (\\d{3}) ([\\x20-\\x7E]*)\\r\\n";

        Pattern r = Pattern.compile(httpResponsePattern);

        Matcher m = r.matcher(packetDataAscii);

        boolean result = m.find();

        if(result){
            return new HttpResponse(Integer.parseInt(m.group(1)), m.group(2), packetDataAscii.substring(packetDataAscii.indexOf("\n")+1));
        } else {
            return new HttpResponse();
        }
    }

    public static String ipv4HexaToHuman(String ipv4Hexa){
        int i;
        String ipv4="";
        for(i=0; i < ipv4Hexa.length(); i+=2){
            ipv4 = ipv4 + Integer.parseInt(ipv4Hexa.substring(i, i+2), 16) + ".";
        }
        return ipv4.substring(0, ipv4.length()-1);
    }

    public static String toPrettyMac(String mac){
        String prettyMac = "";
        for(int i=0; i < mac.length(); i+=2){
            prettyMac = prettyMac + mac.substring(i, i+2) + ":";
        }
        return prettyMac.substring(0, prettyMac.length()-1);
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

    public static String addFlagsPadding(String s, int nb){
        int c = nb - s.length();
        for(int i=0; i<c; i++){
            s = "0"+s;
        }
        return s;
    }

    public static String hexaToAscii(String hex){

        StringBuilder output = new StringBuilder();
        for (int k = 0; k < hex.length(); k+=2) {
            String str = hex.substring(k, k+2);
            output.append((char)Integer.parseInt(str, 16));
        }
        return output.toString();
    }
}
