public class DhcpOption {

    private int optionCode;
    private int optionLength;
    private String optionValue;

    public DhcpOption(int optionCode, int optionLength, String optionValue){
        this.optionCode = optionCode;
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
    
    public String toString(){
        return "\nOption Code : "+optionCode+
        "\nOption Length : "+optionLength+
        "\nOption Value : "+optionValue;
    }
}
