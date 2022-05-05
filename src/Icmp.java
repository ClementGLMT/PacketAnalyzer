package src;
public class Icmp {

    private int type;
    private String typeHuman;
    private int code;
    private String codeHuman;
    private String checksum;
    private String payload;
    private boolean isMatched;

    public Icmp(int type, int code, String checksum, String payload){

        this.type = type;
        this.code = code;
        this.checksum = checksum;
        this.payload = payload;
        this.isMatched = true;
        this.typeHuman = "";
        this.codeHuman = "";

    }

    public Icmp(){

        this.type = 0;
        this.code = 0;
        this.checksum = "";
        this.payload = "";
        this.isMatched = false;
        this.typeHuman = "";
        this.codeHuman = "";

    }

    public boolean isMatched(){
        return isMatched;
    }

    public String toString(){
        resolveHumans();
        return "ICMP "+typeHuman+(codeHuman.equals("No code") ? "" : "\nCode : "+codeHuman)+"\nPayload length: "+(payload.length()/2);
    }

    public void resolveHumans(){
        switch (type) {
            case 0:
                typeHuman = "Echo Reply";
                codeHuman = "No code";
                break;
            case 3:
                typeHuman =  "Destination Unreachable";
                switch (code) {
                    case 0:
                        codeHuman = "Net Unreachable";
                        break;
                    case 1:
                        codeHuman = "Host Unreachable";
                        break;
                    case 2:
                        codeHuman = "Protocol Unreachable";
                        break;
                    case 3:
                        codeHuman = "Port Unreachable";
                        break;
                    case 4:
                        codeHuman = "Fragmentation Needed, and DF was set";
                        break;
                    case 5:
                        codeHuman = "Source route failed";
                        break;
                    case 6:
                        codeHuman = "Destination network unknown";
                        break;
                    case 7:
                        codeHuman = "Destination host unknown";
                        break;
                    case 8:
                        codeHuman = "Source host isolated";
                        break;
                    case 9:
                        codeHuman = "Communication with destination network is administratively prohibited";
                        break;
                    case 10:
                        codeHuman = "Communication with destination host is administratively prohibited";
                        break;
                    case 11:
                        codeHuman = "Destination network unreachable for type of service";
                        break;
                    case 12:
                        codeHuman = "Destination host unreachable for type of service";
                        break;
                    case 13:
                        codeHuman = "Communication administratively prohibited";
                        break;
                    case 14:
                        codeHuman = "Host precedence violation";
                        break;
                    case 15:
                        codeHuman = "Precedence cutoff in effect";
                        break;

                    default:
                        codeHuman = "No code";
                        break;
                }
                break;
            case 5:
                typeHuman =  "Redirect";
                switch (code) {
                    case 0:
                        codeHuman = "Redirect datagram for the network (or subnet)";
                        break;
                    case 1:
                        codeHuman = "Redirect datagram for the host";
                        break;
                    case 2:
                        codeHuman = "Redirect datagram for the type of service and network";
                        break;
                    case 3:
                        codeHuman = "Redirect datagram for the type of service and host";
                        break;
                    default:
                        codeHuman = "No code";
                        break;
                }
                break;
            case 8:
                typeHuman =  "Echo Request";
                codeHuman = "No code";
                break;
            case 9:
                typeHuman =  "Router Advertisement";
                switch (code) {
                    case 0:
                        codeHuman = "Normal router advertisement";
                        break;
                    case 16:
                        codeHuman = "Does not route common traffic";
                        break;
                    default:
                        codeHuman = "No code";
                        break;
                }
                break;
            case 10:
                typeHuman =  "Router Selection";
                switch (code) {
                    case 0:
                        codeHuman = "Time to live exceeded in transit";
                        break;
                    case 1:
                        codeHuman = "Fragment reassembly time exceeded";
                        break;
                    default:
                        codeHuman = "No code";
                        break;
                }
                break;
            case 11:
                typeHuman =  "Time Exceeded";
                codeHuman = "No code";
                break;
            case 12:
                typeHuman =  "Parameter Problem";
                switch (code) {
                    case 0:
                        codeHuman = "Time to live exceeded in transit";
                        break;
                    case 1:
                        codeHuman = "Fragment reassembly time exceeded";
                        break;
                    case 2:
                        codeHuman = "The length is incorrect, suggesting that the packet is missing data";
                        break;
                    default:
                        codeHuman = "No code";
                        break;
                }
                break;
            case 13:
                typeHuman =  "Timestamp";
                codeHuman = "No code";
                break;
            case 14:
                typeHuman =  "Timestamp Reply";
                codeHuman = "No code";
                break;  
            case 40:
                typeHuman =  "Photuris";
                switch (code) {
                    case 0:
                        codeHuman = "Bad SPI";
                        break;
                    case 1:
                        codeHuman = "Authentication Failed";
                        break;
                    case 2:
                        codeHuman = "Decompression failed";
                        break;
                    case 3:
                        codeHuman = "Decryption failed";
                        break;
                    case 4:
                        codeHuman = "Need Authentication";
                        break;
                    case 5:
                        codeHuman = "Need Authorization";
                        break;
                    default:
                        codeHuman = "No code";
                        break;
                }
                break;
            default:
                typeHuman = "Type unknown";
                codeHuman = "No code";
                break;
        }
    }
}
