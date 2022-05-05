package src;
public class Ethernet {
    private String destMacAddress;
    private String sourceMacAddress;
    private String vlanEtherType;
    private String etherType;
    private String etherTypeHuman;
    private boolean isMatched;
    private String ethernerHeaders;


    public Ethernet(String destMacAddress, String sourceMacAddress, String  vlanEtherType, String etherType, String etherTypeHuman, String ethernetHeaders){
        this.destMacAddress = ProtocolParser.toPrettyMac(destMacAddress);
        this.sourceMacAddress = ProtocolParser.toPrettyMac(sourceMacAddress);
        this.vlanEtherType = vlanEtherType;
        this.etherType = etherType;
        this.etherTypeHuman = etherTypeHuman;
        this.isMatched = true;
        this.ethernerHeaders = ethernetHeaders;
    }

    public Ethernet(){
        this.destMacAddress = "";
        this.sourceMacAddress = "";
        this.vlanEtherType = "";
        this.etherType = "";
        this.etherTypeHuman = "";
        this.isMatched = false;
        this.ethernerHeaders = "";
    }

    public String getDestMacAddress(){
        return destMacAddress;
    }

    public String getSourceMacAddress(){
        return sourceMacAddress;
    }

    public String getVlanEtherType(){
        return vlanEtherType;
    }

    public String getEtherType(){
        return etherType;
    }

    public String getetherTypeHuman(){
        return etherTypeHuman;
    }

    public boolean isMatched(){
        return isMatched;
    }

    public String getEthernetData(){
        return ethernerHeaders;
    }

    public String toString(){
        return "MAC : "+sourceMacAddress+(sourceMacAddress.equals("ff:ff:ff:ff:ff:ff") ? " (Broadcast)" : "") +" ----> "+destMacAddress + (destMacAddress.equals("ff:ff:ff:ff:ff:ff") ? " (Broadcast)" : "")/*+"\nEtherType : "+etherType+" ("+etherTypeHuman+")"*/;
    }
    
}
