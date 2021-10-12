public class Arp {

    private String ptype;
    private String ptypeHuman;
    private String plen;
    private String opcode;
    private String senderHardwareAdress;
    private String senderProtocolAddress;
    private String targetHardwareAdress;
    private String targetProtocolAddress;
    private boolean isMatched;
    private String arpHeaders;

    public Arp(String ptype, String ptypeHuman, String plen, String opcode, String senderHardwareAdress, String senderProtocolAddress, String targetHardwareAdress, String targetProtocolAddress, String arpHeaders){
        this.ptype = ptype;
        this.ptypeHuman = ptypeHuman;
        this.plen = plen;
        this.opcode = opcode;
        this.senderHardwareAdress = senderHardwareAdress;
        this.senderProtocolAddress = senderProtocolAddress;
        this.targetHardwareAdress = targetHardwareAdress;
        this.targetProtocolAddress = targetProtocolAddress;
        this.isMatched = true;
        this.arpHeaders = arpHeaders;
    }  

    public Arp(){
        this.ptype = "";
        this.ptypeHuman = "";
        this.plen = "";
        this.opcode = "";
        this.senderHardwareAdress = "";
        this.senderProtocolAddress = "";
        this.targetHardwareAdress = "";
        this.targetProtocolAddress = "";
        this.isMatched = false;
        this.arpHeaders = "";
    }

    private String resolveOpCode(){

        switch (opcode) {
            case "0001":
                return "Request";
            case "0002":
                return "Reply";
            default:
                return "";
        }
    }

    public boolean getIsMatched(){
        return isMatched;
    }

    public String getArpHeaders(){
        return arpHeaders;
    }

    public String toString(){
        return "------ARP------\nProto : "+ptype+" ("+ptypeHuman+")\nOpcode : "+opcode+" ("+resolveOpCode()+")\nSender MAC @ : "+senderHardwareAdress+"\nSender Proto @ : "+senderProtocolAddress+"\nTarget MAC @ : "+targetHardwareAdress+"\nTarget Proto @ : "+targetProtocolAddress;
    }
}