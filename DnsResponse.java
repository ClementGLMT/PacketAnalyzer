public class DnsResponse {

    private String name;
    private String type;
    private String dnsClass;
    private int ttl;
    private int dataLength;
    private String address;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getDnsClass() {
        return dnsClass;
    }

    public void setDnsClass(String dnsClass) {
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

    public DnsResponse(String name, String type, String dnsClass, int ttl, int dataLength, String address) {
        this.name = name;
        this.type = type;
        this.dnsClass = dnsClass;
        this.ttl = ttl;
        this.dataLength = dataLength;
        this.address = address;
    }
    
}
