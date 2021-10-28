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

    public String getOptionCodeHuman(){
        return optionCodeHuman;
    }

    public String getReprOptionValue(){
        return reprOptionValue;
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
                this.reprOptionValue = ""+ProtocolParser.ipv4HexaToHuman(optionValue);
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
                this.reprOptionValue = ""+ProtocolParser.ipv4HexaToHuman(optionValue);
                return "Requested IP";
            case 53:
                this.reprOptionValue = "";
                switch(Integer.parseInt(optionValue, 16)){
                    case 1:
                        this.reprOptionValue += "DHCP DISCOVER";
                        break;
                    case 2:
                        this.reprOptionValue += "DHCP OFFER";
                        break;
                    case 3:
                        this.reprOptionValue += "DHCP REQUEST";
                        break;
                    case 4:
                        this.reprOptionValue += "DHCP DECLINE";
                        break;
                    case 5:
                        this.reprOptionValue += "DHCP ACK";
                        break;
                    case 6:
                        this.reprOptionValue += "DHCP NAK";
                        break;
                    case 7:
                        this.reprOptionValue += "DHCP RELEASE";
                        break;
                    case 8:
                        this.reprOptionValue += "DHCP INFORM";
                        break;
                }
                return "Message type";
            case 12:
                this.reprOptionValue = ""+ProtocolParser.hexaToAscii(optionValue);
                return "Hostname";
            case 1:
                this.reprOptionValue = ""+ProtocolParser.ipv4HexaToHuman(optionValue);
                return "Subnet mask";
            case 6:
                this.reprOptionValue = ""+ProtocolParser.ipv4HexaToHuman(optionValue);
                return "Domain name server";
            case 51:
                this.reprOptionValue = ""+Integer.parseInt(optionValue, 16)+"s";
                return "IP address lease time";
            case 54:
                this.reprOptionValue = ""+ProtocolParser.ipv4HexaToHuman(optionValue);
                return "DHCP Server identifier";
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
