public class DnsQuery {

    private String name;
    private String type;
    private String dnsClass;

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

    public DnsQuery(String name, String type, String dnsClass){
        this.name = name;
        this.type = type;
        this.dnsClass = dnsClass;
    }

    public DnsQuery(){
        this("", "", "");
    }

}
