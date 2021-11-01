package src;
public class DnsQuery {

    private String name;
    private int type;
    private int dnsClass;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public int getType() {
        return type;
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
    public void setType(int type) {
        this.type = type;
    }

    public int getDnsClass() {
        return dnsClass;
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
                return "";
        }
    } 

    public void setDnsClass(int dnsClass) {
        this.dnsClass = dnsClass;
    }

    public DnsQuery(String name, int type, int dnsClass){
        this.name = name;
        this.type = type;
        this.dnsClass = dnsClass;
    }

    public DnsQuery(){
        this("", 0, 0);
    }

}
