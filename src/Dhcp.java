package src;
import java.util.ArrayList;
import java.util.Hashtable;

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
    private Hashtable<Integer, DhcpOption> options;
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
        this.clientMac = ProtocolParser.toPrettyMac(clientMac.substring(0, hlen*2));
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

        this.options = new Hashtable<Integer, DhcpOption>();

        int localCursor = 0;

        int optionCode;

        // While option code is not 255 (end option)
        while((optionCode = Integer.parseInt(optionsString.substring(localCursor, localCursor+=2),16)) != 255){
            
            // Put {optionCode, optionValue} in options dictionary
            int optionLength = Integer.parseInt(optionsString.substring(localCursor, localCursor+=2),16);
            String optionValue = optionsString.substring(localCursor, localCursor += optionLength*2);
            options.put(optionCode, new DhcpOption(optionCode, optionLength, optionValue));
        }

        options.put(255, new DhcpOption(255, 0, ""));
        
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
        String dhcpMessageType = "\n";
        String descr = "";

        DhcpOption msgType = options.get(53);
        switch(Integer.parseInt(msgType.getOptionValue(), 16)){
            case 1:
                descr += msgType.getReprOptionValue()+" ("+getOpCodeHuman()+")"+"\nTRANSACTION ID : "+transacId+"\n\nClient "+clientMac+" is discovering network"/*"\nTransaction id : "+transacId*/;
                break;
            case 2:
                descr += msgType.getReprOptionValue()+" ("+getOpCodeHuman()+")" +"\nTRANSACTION ID : "+transacId+"\n\nServer "+nextServerIp+" is offering to "+clientMac+" :\n\n\t- IP : "+yourClientIp+"\n\t- SUBNET MASK : "+options.get(1).getReprOptionValue()+(options.get(6) == null ? "" : "\n\t- Domain name server : "+options.get(6).getReprOptionValue())+"\n"+(!gatewayIp.equals("0.0.0.0") ? " (DHCP relay : "+gatewayIp+")" : "");
                break;
            case 3:
                descr += msgType.getReprOptionValue()+" ("+getOpCodeHuman()+")" +"\nTRANSACTION ID : "+transacId+"\n\nClient "+clientMac+(!clientIp.equals("0.0.0.0") ? " ("+clientIp+")" : "")+" is requesting address "+(options.get(50) == null ? ""+clientIp : options.get(50).getReprOptionValue())+(options.get(54) == null ? "" : " to DHCP server "+options.get(54).getReprOptionValue());
                break;
            case 5:
                descr += msgType.getReprOptionValue() +" ("+getOpCodeHuman()+")"+"\nTRANSACTION ID : "+transacId+"\n\nServer "+options.get(54).getReprOptionValue()+" is acknowledging configuration for client "+clientMac+(!clientIp.equals("0.0.0.0") ? " ("+clientIp+")" : "")+" :\n\n\t- IP : "+yourClientIp+"\n\t- SUBNET MASK : "+options.get(1).getReprOptionValue()+(options.get(6) == null ? "" : "\n\t- Domain name server : "+options.get(6).getReprOptionValue());
                break;
            default:
                break;
            
        }
        return descr;
    }
    
    
}
