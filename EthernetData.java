public class EthernetData {
    private String destMacAddress;
    private String sourceMacAddress;
    private String vlanEtherType;
    private String etherType;
    private String etherTypeHuman;

    public EthernetData(String destMacAddress, String sourceMacAddress, String  vlanEtherType, String etherType, String etherTypeHuman){
        this.destMacAddress = destMacAddress;
        this.sourceMacAddress = sourceMacAddress;
        this.vlanEtherType = vlanEtherType;
        this.etherType = etherType;
        this.etherTypeHuman = etherTypeHuman;
    }

    public EthernetData(){
        this.destMacAddress = "";
        this.sourceMacAddress = "";
        this.vlanEtherType = "";
        this.etherType = "";
        this.etherTypeHuman = "";
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

    public String toString(){
        return "------ETHERNET------\nSource MAC @ : "+sourceMacAddress+"\nDestination MAC @ : "+destMacAddress+"\nEtherType : "+etherTypeHuman+" ("+etherTypeHuman+")";
    }
    
}
