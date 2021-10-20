import java.util.Dictionary;

public class Dhcp {

    private int opcode;
    private int htype;
    private int hlen;
    private int hops;
    private String transacId;
    private int secondElapsed;
    private String flags;
    private int broadcastFlag;
    private String clientIp;
    private String yourClientIp;
    private String nextServerIp;
    private String gatewayIp;
    private String clientMac;
    private String serverHostName;
    private String bootFile;
    private Dictionary<Integer, String> options;
    private boolean isMatched;

    public Dhcp(int opcode, int htype, int hlen, int hops, String transacId, int secondElapsed, String flags,
            String clientIp, String yourClientIp, String nextServerIp, String gatewayIp, String clientMac,
            String serverHostName, String bootFile, String options) {
        this.opcode = opcode;
        this.htype = htype;
        this.hlen = hlen;
        this.hops = hops;
        this.transacId = transacId;
        this.secondElapsed = secondElapsed;
        this.flags = flags;
        this.clientIp = clientIp;
        this.yourClientIp = yourClientIp;
        this.nextServerIp = nextServerIp;
        this.gatewayIp = gatewayIp;
        this.clientMac = clientMac.substring(0, hlen*2);
        this.serverHostName = serverHostName;
        this.bootFile = bootFile;
        this.isMatched = true;
        // this.options = options;
    }

    public Dhcp() {
        this.opcode = 0;
        this.htype = 0;
        this.hlen = 0;
        this.hops = 0;
        this.transacId = "";
        this.secondElapsed = 0;
        this.flags = "";
        this.clientIp = "";
        this.yourClientIp = "";
        this.nextServerIp = "";
        this.gatewayIp = "";
        this.clientMac = "";
        this.serverHostName = "";
        this.bootFile = "";
        this.isMatched = false;
        // this.options = options;
    }

    private void parseOptions(String options){

    }

    public int getBroadcastFlag(String flagss){
        // ICI
        ProtocolParser.addFlagsPadding(Integer.toBinaryString(Integer.parseInt(flags.substring(0, 2), 16)), 8)
    }

    public boolean getIsMatched(){
        return isMatched;
    }

    public String getOpCodeHuman(){
        switch(opcode){
            case 1:
                return "Boot Request";
            case 2:
                return "Boot Reply";
            default:
                return "";
        }
    }

    public String toString(){
        return "------DHCP------\nOpcode : "+opcode+" ("+getOpCodeHuman()+")\nHardware type : "+htype+"\nHarware Len : "+hlen+"\nHops : "+hops+"\nTransaction ID : "+transacId+"\nSecond elapsed : "+secondElapsed+"\nFlags : "+flags+"\nClient IP : "+clientIp+"\nYour Client IP : "+yourClientIp+"\nNext Server IP : "+nextServerIp+"\nGateway IP : "+gatewayIp+"\nClient MAC : "+clientMac+"\nServer Hostname : "+serverHostName+"\nBoot File : "+bootFile+"\nOptions : "+options;
    }
    
    
}
