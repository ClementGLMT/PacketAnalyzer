import java.util.ArrayList;
import java.util.Map;

public class PacketAnalyzer {
    public static void main(String[] args){

        PcapReader pcapReader = new PcapReader("capture.pcap");

        Map<String, Object> headers = pcapReader.getFileHeaders();

        ArrayList<Packet> packetList = pcapReader.getPacketList();

        System.out.println("File headers\n");
        System.out.println(headers+"\n");

        for (Packet packet : packetList) {
            System.out.println(packet);
        }
        ProtocolParser pparser = new ProtocolParser(packetList.get(0).getPacketData());
        System.out.println(pparser.recognizeARP());
    }
}
