public class Udp {

    private int sourcePort;
    private int destinationPort;
    private int length;
    private String checksum;
    private boolean isMatched;
    private String udpHeaders;
    private String udpData;


    public Udp(int sourcePort, int destinationPort, int length, String checksum, String udpHeaders, String udpData){
        this.sourcePort = sourcePort;
        this.destinationPort = destinationPort;
        this.length = length;
        this.checksum = checksum;
        this.udpHeaders = udpHeaders;
        this.udpData = udpData;
        this.isMatched = true;
    }

    public Udp(){
        this.sourcePort = 0;
        this.destinationPort = 0;
        this.length = 0;
        this.checksum = "";
        this.udpHeaders = "";
        this.udpData = "";
        this.isMatched = false;
    }

    public boolean isMatched(){
        return isMatched;
    }

    public String toString(){
        return ""+length+" Bytes payload";
        // return "------UDP------\nPayload length : "+length+"\n\nPORTS : "+sourcePort+" ----> "+destinationPort;
    }

    public String getUdpHeaders(){
        return udpHeaders;
    }

    public String getUdpData(){
        return udpData;
    }

    public int getDestPort(){
        return destinationPort;
    }

    public int getSourcePort(){
        return sourcePort;
    }
    
}
