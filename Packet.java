import java.util.Hashtable;
import java.util.Map;

public class Packet {
    private Map<String, Object> packetHeaders;
    private String packetData;

    public Packet(Map<String, Object> packetHeaders, String packetData){
        this.packetHeaders = packetHeaders;
        this.packetData = packetData;
    }

    public Packet() {
        this.packetHeaders = new Hashtable<String, Object>();
        this.packetData = "";
    }

    public int getPacketSize(){
        return (int) packetHeaders.get("incl_len");
    }

    public Map<String, Object> getPacketHeaders(){
        return this.packetHeaders;
    }

    public String getPacketData(){
        return this.packetData;
    }

    public void setPacketHeaders(Map<String, Object> packetHeaders){
        this.packetHeaders = packetHeaders;
    }

    public void setPacketData(String packetData){
        this.packetData = packetData;
    }

    public String toString(){
        return "\n\nHEADERS : " + this.packetHeaders + "\nDATA : " + this.packetData;
    }

}
