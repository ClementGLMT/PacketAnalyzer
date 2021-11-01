package src;
import java.util.Hashtable;
import java.util.Map;

public class Packet {

    private Map<String, Object> packetHeaders;
    private String packetData;

    private Packet reassembledPacket;

    private Ethernet eth;
    
    private Arp arp;
    private IPv4 ipv4;

    private Icmp icmp;
    private Tcp tcp;
    private Udp udp;

    private Dhcp dhcp;
    private Ftp ftp;
    private FtpData ftpData;
    private Dns dns;
    private HttpRequest httpRequest;
    private HttpResponse httpResponse;

    private boolean dnsRegexMatch;

    private String debug;

    public Packet(Map<String, Object> packetHeaders, String packetData){
        this.packetHeaders = packetHeaders;
        this.packetData = packetData;
        this.reassembledPacket = new Packet();

        this.eth = new Ethernet();
        this.arp = new Arp();
        this.ipv4 = new IPv4();
        this.icmp = new Icmp();
        this.tcp = new Tcp();
        this.udp = new Udp();
        this.dhcp = new Dhcp();
        this.ftp = new Ftp();
        this.ftpData = new FtpData();
        this.dns = new Dns();
        this.httpRequest = new HttpRequest();
        this.httpResponse = new HttpResponse();
        this.dnsRegexMatch = false;
        this.debug = "";
    }

    public Packet() {
        this.packetHeaders = new Hashtable<String, Object>();
        this.packetData = "";
        this.reassembledPacket = null;

        this.eth = new Ethernet();
        this.arp = new Arp();
        this.ipv4 = new IPv4();
        this.icmp = new Icmp();
        this.tcp = new Tcp();
        this.udp = new Udp();
        this.dhcp = new Dhcp();
        this.ftp = new Ftp();
        this.ftpData = new FtpData();
        this.dns = new Dns();
        this.httpRequest = new HttpRequest();
        this.httpResponse = new HttpResponse();
        this.dnsRegexMatch = false;
        this.debug = "";
    }

    public Packet(Packet p){
        this.packetHeaders = p.getPacketHeaders();
        this.packetData = p.getPacketData();
        this.reassembledPacket = p.getReassembledPacket();

        this.eth = p.getEth();
        this.arp = p.getArp();
        this.ipv4 = new IPv4(p.getIpv4());
        this.icmp = p.getIcmp();
        this.tcp = p.getTcp();
        this.udp = p.getUdp();
        this.dhcp = p.getDhcp();
        this.ftp = p.getFtp();
        this.ftpData = p.getFtpData();
        this.dns = p.getDns();
        this.httpRequest = p.getHttpRequest();
        this.httpResponse = p.getHttpResponse();
        this.dnsRegexMatch = p.isDnsRegexMatch();
        this.debug = p.debug;
    }

    public Packet getReassembledPacket() {
        return reassembledPacket;
    }

    public void assignReassembledPacket(Packet reassembledPacket) {
        this.reassembledPacket = reassembledPacket;
    }

    public Packet addDebug(String d){
        this.debug += d+"\n";
        return this;
    }

    public void printDebug(){
        System.out.println(debug);
    }

    public boolean hasDebug(){
        return !this.debug.equals("");
    }

    public boolean isDnsRegexMatch() {
        return dnsRegexMatch;
    }

    public Packet setDnsRegexMatch(boolean dnsRegexMatch) {
        this.dnsRegexMatch = dnsRegexMatch;
        return this;
    }

    public Packet addEthernet(Ethernet eth){
        this.eth = eth;
        return this;
    }

    public Packet addArp(Arp arp){
        this.arp = arp;
        return this;
    }

    public Packet addIpv4(IPv4 ipv4){
        this.ipv4 = ipv4;
        return this;
    }

    public Packet addIcmp(Icmp icmp){
        this.icmp = icmp;
        return this;
    }

    public Packet addTcp(Tcp tcp){
        this.tcp = tcp;
        return this;
    }

    public Packet addUdp(Udp udp){
        this.udp = udp;
        return this;
    }

    public Packet addDhcp(Dhcp dhcp){
        this.dhcp = dhcp;
        return this;
    }

    public Packet addDns(Dns dns){
        this.dns = dns;
        return this;
    }

    public Packet addFtp(Ftp ftp){
        this.ftp = ftp;
        return this;
    }

    public Packet addHttpRequest(HttpRequest httpRequest){
        this.httpRequest = httpRequest;
        return this;
    }

    public Packet addHttpResponse(HttpResponse httpResponse){
        this.httpResponse = httpResponse;
        return this;
    }

    public Packet addFtpData(FtpData ftpData){
        this.ftpData = ftpData;
        return this;
    }

    public Ethernet getEth() {
        return eth;
    }

    public Arp getArp() {
        return arp;
    }

    public IPv4 getIpv4() {
        return this.ipv4;
    }

    public Icmp getIcmp() {
        return icmp;
    }

    public Tcp getTcp() {
        return tcp;
    }

    public Udp getUdp() {
        return udp;
    }

    public Dhcp getDhcp() {
        return dhcp;
    }

    public Ftp getFtp() {
        return ftp;
    }

    public FtpData getFtpData(){
        return ftpData;
    }

    public Dns getDns() {
        return dns;
    }

    public HttpRequest getHttpRequest() {
        return httpRequest;
    }

    public HttpResponse getHttpResponse() {
        return httpResponse;
    }

    public int getPacketSize(){
        return (int) packetHeaders.get("incl_len");
    }

    public Map<String, Object> getPacketHeaders(){
        return this.packetHeaders;
    }

    public String getPacketData(){
        return this.packetData;
    }

    public void setPacketHeaders(Map<String, Object> packetHeaders){
        this.packetHeaders = packetHeaders;
    }

    public void setPacketData(String packetData){
        this.packetData = packetData;
    }

    public void setEth(Ethernet eth) {
        this.eth = eth;
    }

    public void setArp(Arp arp) {
        this.arp = arp;
    }

    public void setIpv4(IPv4 ipv4) {
        this.ipv4 = ipv4;
    }

    public void setIcmp(Icmp icmp) {
        this.icmp = icmp;
    }

    public void setTcp(Tcp tcp) {
        this.tcp = tcp;
    }

    public void setUdp(Udp udp) {
        this.udp = udp;
    }

    public void setDhcp(Dhcp dhcp) {
        this.dhcp = dhcp;
    }

    public void setFtp(Ftp ftp) {
        this.ftp = ftp;
    }

    public void setFtpData(FtpData ftpData) {
        this.ftpData = ftpData;
    }

    public void setDns(Dns dns) {
        this.dns = dns;
    }

    public void setHttpRequest(HttpRequest httpRequest) {
        this.httpRequest = httpRequest;
    }

    public void setHttpResponse(HttpResponse httpResponse) {
        this.httpResponse = httpResponse;
    }

    public String getDebug() {
        return debug;
    }

    public void setDebug(String debug) {
        this.debug = debug;
    }

    public String summary(){

        String protosSummary = "";

        if(eth.isMatched()){
            protosSummary += "[ETHERNET] / ";
        }
        if(arp.isMatched()){
            protosSummary += "[ARP] / ";
        }

        if(ipv4.isMatched()){
            protosSummary += "[IPv4] / ";
        }

        if(tcp.isMatched()){
            protosSummary += "[TCP] / ";
        }

        if(udp.isMatched()){
            protosSummary += "[UDP] / ";
        }

        if(icmp.isMatched()){
            protosSummary += "[ICMP] / ";
        }

        if(dns.isMatched()){
            protosSummary += "[DNS] / ";
        }

        if(dhcp.isMatched()){
            protosSummary += "[DHCP] / ";
        }

        if(ftp.isMatched()){
            protosSummary += "[FTP] / ";
        }

        if(ftpData.isMatched()){
            protosSummary += "[FTP-DATA] / ";
        }

        if(httpRequest.isMatched() || httpResponse.isMatched()){
            protosSummary += "[HTTP] / ";
        }

        protosSummary = protosSummary.substring(0, protosSummary.length()-3);

        String r = "\n" + protosSummary+"\n\n";

        if(!ipv4.isMatched() && !tcp.isMatched() && !udp.isMatched() && !icmp.isMatched() && !dns.isMatched() && !dhcp.isMatched() && !ftp.isMatched() && !ftpData.isMatched() && !httpRequest.isMatched() && !httpResponse.isMatched()){
            r += "\n"+eth.toString();
        }

        if(arp.isMatched()){
            r += "\n\n"+arp.toString();

        } else {
            if(ipv4.isMatched()){

                if(tcp.isMatched()){
                    r += "\n"+tcp.toString();
                    r += "\nTCP over IPv4 : "+ipv4.getSourceAddress()+":"+tcp.getSourcePort()+" ----> "+ipv4.getDestinationAddress()+":"+tcp.getDestinationPort();
                }
        
                if(udp.isMatched()){
                    r += "\nUDP over IPv4 : "+ipv4.getSourceAddress()+":"+udp.getSourcePort()+" ----> "+ipv4.getDestinationAddress()+":"+udp.getDestPort() +(ipv4.getDestinationAddress().equals("255.255.255.255") ? " (Broadcast)" : "");
                    r += "\n"+udp.toString();
                }

                if(dns.isMatched()){
                    r += "\n\n"+dns.toString();
                }

                if(dhcp.isMatched()){
                    r += "\n\n"+dhcp.toString();
                }

                if(ftp.isMatched()){
                    r += "\n\n"+ftp.toString();
                }

                if(ftpData.isMatched()){
                    r += "\n\n"+ftpData.toString();
                }

                if(httpRequest.isMatched()){
                    r += "\n\n"+httpRequest.toString();
                }

                if(httpResponse.isMatched()){
                    r += "\n\n"+httpResponse.toString();
                }

                if(!tcp.isMatched() && !udp.isMatched() && !icmp.isMatched() && !dns.isMatched() && !dhcp.isMatched() && !ftp.isMatched() && !ftpData.isMatched() && !httpRequest.isMatched() && !httpResponse.isMatched()){
                    r += "\n"+ipv4.toString();
                    r += "\n"+eth.toString();
                }

                // ICMP c'est good
                if(icmp.isMatched()){
                    r += "\n"+icmp.toString();
                    r += "\n\n"+ipv4.toString();
                    if(eth.isMatched()){
                        r += "\n"+eth.toString();
                    }
                } 
            }

        }

        return r;
    }

    public String toString(){
        String r = "";

        if(eth.isMatched())
            r += "\n"+eth.toString();

        if(arp.isMatched())
            r += "\n\n"+arp.toString();
        if(ipv4.isMatched())
            r += "\n\n"+ipv4.toString();

        if(icmp.isMatched())
            r += "\n\n"+icmp.toString();
        if(tcp.isMatched())
            r += "\n\n"+tcp.toString();
        if(udp.isMatched())
            r += "\n\n"+udp.toString();

        if(dhcp.isMatched())
            r += "\n\n"+dhcp.toString();
        if(ftp.isMatched())
            r += "\n\n"+ftp.toString();
        if(ftpData.isMatched())
            r += "\n\n"+ftpData.toString();
        if(dns.isMatched())
            r += "\n\n"+dns.toString();
        if(httpRequest.isMatched())
            r += "\n\n"+httpRequest.toString();
        if(httpResponse.isMatched())
            r += "\n\n"+httpResponse.toString();

        return r;
    }

}
