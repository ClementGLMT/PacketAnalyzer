package src;
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
        this.senderHardwareAdress = ProtocolParser.toPrettyMac(senderHardwareAdress);
        this.senderProtocolAddress = senderProtocolAddress;
        this.targetHardwareAdress = ProtocolParser.toPrettyMac(targetHardwareAdress);
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

    public boolean isMatched(){
        return isMatched;
    }

    public String getArpHeaders(){
        return arpHeaders;
    }

    public String toString(){
        String descr = "";
        switch(opcode){
            case "0001":
                descr = "What is your hardware address "+targetProtocolAddress+" ? Tell "+senderProtocolAddress+ (senderProtocolAddress.equals("0.0.0.0") ? " (Broadcast)" : "");
                break;
            case "0002":
                descr = "I'm "+senderProtocolAddress+", my hardware address is : "+senderHardwareAdress;
                break;
            default:
                break;
        }
        return "ARP "+resolveOpCode()+"\nLayer 3 protocol : "+ptypeHuman+"\nHARDWARE : "+senderHardwareAdress+" ----> "+targetHardwareAdress+ (targetHardwareAdress.equals("ff:ff:ff:ff:ff:ff") ? " (Broadcast)" : "") +"\n\n"+descr;
    }
}