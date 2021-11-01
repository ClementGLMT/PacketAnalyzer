package src;
public class IPv4 {

    private int headerLength;
    private int headerLengthBytes;
    private String ds;
    private int totalLength;
    private String identification;
    private String flags;
    private String fragmentOffset;
    private String ttl;
    private String protocol;
    private String headerChecksum;
    private String sourceAdress;
    private String destinationAdress;
    private String options;
    private String ipv4Headers;
    private boolean isMatched;
    private String payload;

    private int dontFragment;
    private int moreFragment;
    private int intFragmentOffset;

    public IPv4(int headerLength, String ds, int totalLength, String identification,String flags,String fragmentOffset,String ttl,String protocol,String headerChecksum,String sourceAdress,String destinationAdress, String options , String ipv4Headers){
        
        this.headerLength = headerLength;
        this.headerLengthBytes = headerLength*4;
        this.ds = ds;
        this.totalLength = totalLength;
        this.identification = identification;
        this.flags = ProtocolParser.addFlagsPadding(Integer.toBinaryString(Integer.parseInt(flags, 16)), 16);

        this.resolveFlags(this.flags);

        this.ttl = ttl;
        this.protocol = protocol;
        this.headerChecksum = headerChecksum;
        this.sourceAdress = sourceAdress;
        this.destinationAdress = destinationAdress;
        this.options = options;
        this.ipv4Headers = ipv4Headers;
        this.payload = "";
        this.isMatched = true;
    }

    public IPv4(){

        this.headerLength = 0;
        this.ds = "";
        this.totalLength = 0;
        this.identification = "";
        this.flags = "";
        this.fragmentOffset = "";
        this.ttl = "";
        this.protocol = "";
        this.headerChecksum = "";
        this.sourceAdress = "";
        this.destinationAdress = "";
        this.ipv4Headers = "";
        this.isMatched = false;
    }

    public IPv4(IPv4 ipv4){
        this.headerLength = ipv4.getHeaderLength();
        this.headerLengthBytes = ipv4.getHeaderLengthBytes();
        this.ds = ipv4.getDs();
        this.totalLength = ipv4.getTotalLength();
        this.identification = ipv4.getIdentification();
        this.flags = ipv4.getFlags();
        this.fragmentOffset = ipv4.getFragmentOffset();
        this.ttl = ipv4.getTtl();
        this.protocol = ipv4.getProtocol();
        this.headerChecksum = ipv4.getHeaderChecksum();
        this.sourceAdress = ipv4.getSourceAddress();
        this.destinationAdress = ipv4.getDestinationAddress();
        this.options = ipv4.getOptions();
        this.ipv4Headers = ipv4.getIpv4Headers();
        this.isMatched = ipv4.isMatched();
        this.payload = ipv4.getPayload();
    
        this.dontFragment = ipv4.getDontFragment();
        this.moreFragment = ipv4.getMoreFragment();
        this.intFragmentOffset = ipv4.getIntFragmentOffset();
    }

    public String toString(){
        return "IPv4 : "+sourceAdress+" ----> "+destinationAdress;
    }

    public boolean isMatched(){
        return isMatched;
    }

    public String getIpv4Headers(){
        return ipv4Headers;
    }

    public String resolveTransportProtocol(){
        switch (protocol) {
            case "06":
                return "TCP";
            case "11":
                return "UDP";
            case "01":
                return "ICMP";
            default:
                return "";
        }
    }

    private void resolveFlags(String myFlags){

        dontFragment = Character.getNumericValue(myFlags.charAt(1));
        moreFragment = Character.getNumericValue(myFlags.charAt(2));
        this.fragmentOffset = myFlags.substring(3);
        this.intFragmentOffset = Integer.parseInt(this.fragmentOffset, 2);
 
    }

    public String getPayload(){
        return payload;
    }

    public void setPayload(String payload){
        this.payload = payload;
    }

    public int getPayloadLength(){
        return payload.length()/2;
    }

    public int getDontFragment(){
        return dontFragment;
    }

    public int getMoreFragment(){
        return moreFragment;
    }

    public void setMoreFragment(int moreFragment){
        this.moreFragment = moreFragment;
    }

    public int getIntFragmentOffset(){
        return intFragmentOffset;
    }

    public void setIntFragmentOffset(int fragmentOffset){
        this.intFragmentOffset = fragmentOffset;
    }

    public int getFragmentOffsetBytes(){
        return intFragmentOffset*8;
    }

    public int getHeaderLength(){
        return headerLength;
    }

    public int getTotalLength(){
        return totalLength;
    }

    public String getTransportProtocol(){
        return protocol;
    }

    public int getHeaderLengthBytes(){
        return headerLengthBytes;
    }

    public String getSourceAddress(){
        return sourceAdress;
    }

    public String getDestinationAddress(){
        return destinationAdress;
    }

    public String getIdentification(){
        return identification;
    }

    public void setHeaderLength(int headerLength) {
        this.headerLength = headerLength;
    }

    public void setHeaderLengthBytes(int headerLengthBytes) {
        this.headerLengthBytes = headerLengthBytes;
    }

    public String getDs() {
        return ds;
    }

    public void setDs(String ds) {
        this.ds = ds;
    }

    public void setTotalLength(int totalLength) {
        this.totalLength = totalLength;
    }

    public void setIdentification(String identification) {
        this.identification = identification;
    }

    public String getFlags() {
        return flags;
    }

    public void setFlags(String flags) {
        this.flags = flags;
    }

    public String getFragmentOffset() {
        return fragmentOffset;
    }

    public void setFragmentOffset(String fragmentOffset) {
        this.fragmentOffset = fragmentOffset;
    }

    public String getTtl() {
        return ttl;
    }

    public void setTtl(String ttl) {
        this.ttl = ttl;
    }

    public String getProtocol() {
        return protocol;
    }

    public void setProtocol(String protocol) {
        this.protocol = protocol;
    }

    public String getHeaderChecksum() {
        return headerChecksum;
    }

    public void setHeaderChecksum(String headerChecksum) {
        this.headerChecksum = headerChecksum;
    }

    public String getSourceAdress() {
        return sourceAdress;
    }

    public void setSourceAdress(String sourceAdress) {
        this.sourceAdress = sourceAdress;
    }

    public String getDestinationAdress() {
        return destinationAdress;
    }

    public void setDestinationAdress(String destinationAdress) {
        this.destinationAdress = destinationAdress;
    }

    public String getOptions() {
        return options;
    }

    public void setOptions(String options) {
        this.options = options;
    }

    public void setIpv4Headers(String ipv4Headers) {
        this.ipv4Headers = ipv4Headers;
    }

    public void setMatched(boolean isMatched) {
        this.isMatched = isMatched;
    }

    public void setDontFragment(int dontFragment) {
        this.dontFragment = dontFragment;
    }

    
}
