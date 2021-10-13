public class IPv4 {

    private int headerLength;
    private int headerLengthBytes;
    private String ds;
    private int totalLength;
    private String identification;
    private String flags;
    private String fragmentOffset;
    private String ttl;
    private String protocol;
    private String headerChecksum;
    private String sourceAdress;
    private String destinationAdress;
    private String ipv4Headers;
    private boolean isMatched;

    public IPv4(int headerLength, String ds, int totalLength, String identification,String flags,String fragmentOffset,String ttl,String protocol,String headerChecksum,String sourceAdress,String destinationAdress, String ipv4Headers){
        
        this.headerLength = headerLength;
        this.headerLengthBytes = headerLength*4;
        this.ds = ds;
        this.totalLength = totalLength;
        this.identification = identification;
        this.flags = flags;
        this.fragmentOffset = fragmentOffset;
        this.ttl = ttl;
        this.protocol = protocol;
        this.headerChecksum = headerChecksum;
        this.sourceAdress = sourceAdress;
        this.destinationAdress = destinationAdress;
        this.ipv4Headers = ipv4Headers;
        this.isMatched = true;
    }

    public IPv4(){

        this.headerLength = 0;
        this.ds = "";
        this.totalLength = 0;
        this.identification = "";
        this.flags = "";
        this.fragmentOffset = "";
        this.ttl = "";
        this.protocol = "";
        this.headerChecksum = "";
        this.sourceAdress = "";
        this.destinationAdress = "";
        this.ipv4Headers = "";
        this.isMatched = false;
    }

    public String toString(){
        return "------IPv4------\nHeader Length : "+headerLength+" ("+headerLengthBytes+" bytes)\nDS : "+ds+"\nTotal Length : "+totalLength+"\nIdentification : "+identification+"\nFlags : "+flags+"\nFragment Offset : "+fragmentOffset+"\nTTL : "+ttl+"\nProtocol : "+protocol+" ("+resolveTransportProtocol()+")\nHeader Checksum : "+headerChecksum+"\nSource @ : "+sourceAdress+"\nDestination @ : "+destinationAdress;
    }

    public boolean getIsMatched(){
        return isMatched;
    }

    public String getIpv4Headers(){
        return ipv4Headers;
    }

    public String resolveTransportProtocol(){
        switch (protocol) {
            case "06":
                return "TCP";
            case "11":
                return "UDP";
            case "01":
                return "ICMP";
            default:
                return "";
        }
    }

    public int getHeaderLength(){
        return headerLength;
    }

    public int getTotalLength(){
        return totalLength;
    }

    public String getTransportProtocol(){
        return protocol;
    }

    public int getHeaderLengthBytes(){
        return headerLengthBytes;
    }
}
