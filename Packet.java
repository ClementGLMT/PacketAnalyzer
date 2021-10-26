import java.util.Hashtable;
import java.util.Map;

public class Packet {

    private Map<String, Object> packetHeaders;
    private String packetData;

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
        return ipv4;
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

    public String toString(){
        String r = "\n\n";

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

        return "\n\nHEADERS : " + this.packetHeaders + "\nDATA : " + this.packetData+r;
    }

}
