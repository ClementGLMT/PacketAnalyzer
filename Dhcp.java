import java.util.ArrayList;

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
    private ArrayList<DhcpOption> options;
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
        this.flags = ProtocolParser.addFlagsPadding(Integer.toBinaryString(Integer.parseInt(flags.substring(0, 2), 16)), 16);
        this.clientIp = clientIp;
        this.yourClientIp = yourClientIp;
        this.nextServerIp = nextServerIp;
        this.gatewayIp = gatewayIp;
        this.clientMac = clientMac.substring(0, hlen*2);
        this.serverHostName = serverHostName;
        this.bootFile = bootFile;
        this.isMatched = true;
        getBroadcastFlag(this.flags);
        parseOptions(options);
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

    private void parseOptions(String optionsString){

        this.options = new ArrayList<DhcpOption>();

        int localCursor = 0;

        int optionCode;

        // While option code is not 255 (end option)
        while((optionCode = Integer.parseInt(optionsString.substring(localCursor, localCursor+=2),16)) != 255){
            
            // Put {optionCode, optionValue} in options dictionary
            int optionLength = Integer.parseInt(optionsString.substring(localCursor, localCursor+=2),16);
            String optionValue = optionsString.substring(localCursor, localCursor += optionLength*2);
            options.add(new DhcpOption(optionCode, optionLength, optionValue));
        }

        options.add(new DhcpOption(255, 0, ""));
        
    }

    public void getBroadcastFlag(String flagss){

        this.broadcastFlag = Character.getNumericValue(flagss.charAt(0));
    }

    public boolean isMatched(){
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
        String optionsString = "";
        for (DhcpOption dhcpOption : options) {
            optionsString += dhcpOption.toString();
        }
        return "------DHCP------\nOpcode : "+opcode+" ("+getOpCodeHuman()+
        ")\nHardware type : "+htype+
        "\nHarware Len : "+hlen+
        "\nHops : "+hops+
        "\nTransaction ID : "+transacId+
        "\nSecond elapsed : "+secondElapsed+
        "\nFlags : "+flags+
        "\nBroadcast Flag : "+this.broadcastFlag+
        "\nClient IP : "+clientIp+
        "\nYour Client IP : "+yourClientIp+
        "\nNext Server IP : "+nextServerIp+
        "\nGateway IP : "+gatewayIp+
        "\nClient MAC : "+clientMac+
        "\nServer Hostname : "+serverHostName+
        "\nBoot File : "+bootFile+
        "\nOptions : "+optionsString;
    }
    
    
}
