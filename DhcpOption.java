public class DhcpOption {

    private int optionCode;
    private String optionCodeHuman;
    private int optionLength;
    private String optionValue;
    private String reprOptionValue;

    public DhcpOption(int optionCode, int optionLength, String optionValue){
        this.optionCode = optionCode;
        this.optionCodeHuman = resolveOptionCode(optionCode, optionValue);
        this.optionLength = optionLength;
        this.optionValue = optionValue;
    }

    public int getOptionCode() {
        return optionCode;
    }

    public void setOptionCode(int optionCode) {
        this.optionCode = optionCode;
    }

    public int getOptionLength() {
        return optionLength;
    }

    public void setOptionLength(int optionLength) {
        this.optionLength = optionLength;
    }

    public String getOptionValue() {
        return optionValue;
    }

    public void setOptionValue(String optionValue) {
        this.optionValue = optionValue;
    }

    private String resolveOptionCode(int optionCode, String optionValue){
        switch(optionCode){
            case 3:
                this.reprOptionValue = "Gateway IP : "+ProtocolParser.ipv4HexaToHuman(optionValue);
                return "Gateway";
            case 19:
                this.reprOptionValue = (Integer.parseInt(optionValue, 16) == 1) ? "Enable" : "Disable" + "IP Forwarding";
                return "IP Forwarding";
            case 20:
                this.reprOptionValue = (Integer.parseInt(optionValue, 16) == 1) ? "Enable" : "Disable" + "Non local source Routing";
                return "Non local source Routing";
            case 61:
                this.reprOptionValue = (optionValue.substring(0, 2) == "01") ? "Ethernet : " : "" + optionValue.substring(2);
                return "Client identifier";
            case 50:
                this.reprOptionValue = "Requested IP : "+ProtocolParser.ipv4HexaToHuman(optionValue);
                return "Requested IP";
            case 53:
                this.reprOptionValue = "Message type : ";
                switch(Integer.parseInt(optionValue, 16)){
                    case 1:
                        this.reprOptionValue += "DHCPDISCOVER";
                        break;
                    case 2:
                        this.reprOptionValue += "DHCPOFFER";
                        break;
                    case 3:
                        this.reprOptionValue += "DHCPREQUEST";
                        break;
                    case 4:
                        this.reprOptionValue += "DHCPDECLINE";
                        break;
                    case 5:
                        this.reprOptionValue += "DHCPACK";
                        break;
                    case 6:
                        this.reprOptionValue += "DHCPNAK";
                        break;
                    case 7:
                        this.reprOptionValue += "DHCPRELEASE";
                        break;
                    case 8:
                        this.reprOptionValue += "DHCPINFORM";
                        break;
                }
                return "Message type";
            case 12:
                this.reprOptionValue = "Hostname : "+ProtocolParser.hexaToAscii(optionValue);
                return "Hostname";
            case 1:
                this.reprOptionValue = "Subnet mask : "+ProtocolParser.ipv4HexaToHuman(optionValue);
                return "Subnet mask";
            case 6:
                this.reprOptionValue = "Domain name server : "+ProtocolParser.ipv4HexaToHuman(optionValue);
                return "Domain name server";
            case 51:
                this.reprOptionValue = "IP address lease time : "+Integer.parseInt(optionValue, 16)+"s";
                return "IP address lease time";
            default:
                this.reprOptionValue = "";
                return "";
        }
    }
    
    public String toString(){
        String optionCodeString = "\nOption Code : "+optionCode;
        optionCodeString += (optionCodeHuman.equals("")) ? "" : " ("+optionCodeHuman+")";
        return optionCodeString+ 
        "\nOption Length : "+optionLength+
        "\n"+reprOptionValue;
    }
}
