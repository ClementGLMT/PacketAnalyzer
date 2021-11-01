package src;
public class DnsResponse {

    private String name;
    private int type;
    private int dnsClass;
    private int ttl;
    private int dataLength;
    private String address;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public int getType() {
        return type;
    }

    public void setType(int type) {
        this.type = type;
    }

    public int getDnsClass() {
        return dnsClass;
    }

    public void setDnsClass(int dnsClass) {
        this.dnsClass = dnsClass;
    }

    public int getTtl() {
        return ttl;
    }

    public void setTtl(int ttl) {
        this.ttl = ttl;
    }

    public int getDataLength() {
        return dataLength;
    }

    public void setDataLength(int dataLength) {
        this.dataLength = dataLength;
    }

    public String getAddress() {
        return address;
    }

    public void setAddress(String address) {
        this.address = address;
    }

    public String getTypeHuman(){
        switch(type){
            case 1:
                return "A (Host Address)";
            case 2:
                return "NS (Name Server)";
            case 15:
                return "MX (Mail Exchange)";
            case 28:
                return "AAAA (IPv6 Address)";
            case 5:
                return "CNAME (Canonical NAME for an Alias)";
            default:
                return "Type not supported";
        }
    }

    public String getDnsClassHuman(){
        switch(dnsClass){
            case 1:
                return "IN (Internet)";
            case 3:
                return "CH (Chaos)";
            case 4:
                return "HS (Hesiod)";
            default:
                return "Class not supported";
        }
    } 

    public DnsResponse(String name, int type, int dnsClass, int ttl, int dataLength, String address) {
        this.name = name;
        this.type = type;
        this.dnsClass = dnsClass;
        this.ttl = ttl;
        this.dataLength = dataLength;
        this.address = address;
    }

    public DnsResponse() {
        this("", 0, 0, 0, 0, "");
    }
    
}
