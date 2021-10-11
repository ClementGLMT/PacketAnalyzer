import java.util.ArrayList;
import java.util.Map;

public class PacketAnalyzer {
    public static void main(String[] args){
        int i;

        PcapReader pcapReader = new PcapReader("capture-arp.pcap");

        Map<String, Object> headers = pcapReader.getFileHeaders();

        ArrayList<Packet> packetList = pcapReader.getPacketList();

        System.out.println("File headers\n");
        System.out.println(headers+"\n");

        for (i=0; i < packetList.size(); i++) {
            System.out.println("\n------------Packet "+i+"------------");
            System.out.println("Packet Data :\n"+packetList.get(i).getPacketData());
            ProtocolParser pparser = new ProtocolParser(packetList.get(i).getPacketData());
            System.out.println(pparser.recognizeEthernet());
        }

    }
}
