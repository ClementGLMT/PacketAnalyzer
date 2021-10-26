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
    private Dns dns;
    private HttpRequest httpRequest;
    private HttpResponse httpResponse;

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
        this.dns = new Dns();
        this.httpRequest = new HttpRequest();
        this.httpResponse = new HttpResponse();
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
        this.dns = new Dns();
        this.httpRequest = new HttpRequest();
        this.httpResponse = new HttpResponse();
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
            r += eth.toString();

        if(arp.isMatched())
            r += arp.toString();
        if(ipv4.isMatched())
            r += ipv4.toString();

        if(icmp.isMatched())
            r += icmp.toString();
        if(tcp.isMatched())
            r += tcp.toString();
        if(udp.isMatched())
            r += udp.toString();

        if(dhcp.isMatched())
            r += dhcp.toString();
        if(ftp.isMatched())
            r += ftp.toString();
        if(dns.isMatched())
            r += dns.toString();
        if(httpRequest.isMatched())
            r += httpRequest.toString();
        if(httpResponse.isMatched())
            r += httpResponse.toString();

        return "\n\nHEADERS : " + this.packetHeaders + "\nDATA : " + this.packetData+r;
    }

}
