import java.io.File;
import java.io.FileInputStream;
import java.util.Map;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Hashtable;

public class PcapReader {
    private String[] hexBuff;
    private int fileCursor;

  public PcapReader(String filename){
    fileCursor = 0;
    readFile(filename);
  }

  private void readFile(String filename){
    FileInputStream fileInputStream = null;

    File pcap = new File(filename);

    byte[] bFile = new byte[(int) pcap.length()];
    hexBuff = new String[bFile.length];

    try
      {
         fileInputStream = new FileInputStream(pcap);
         fileInputStream.read(bFile);
         fileInputStream.close();

         for (int i = 0; i < bFile.length; i++)
         {
            hexBuff[i] = String.format("%02x", bFile[i]);
            //System.out.print(hexBuff[i]);
         }
      }
      catch (Exception e)
      {
        e.printStackTrace();
      }
  }

  public Map<String, Object> getFileHeaders(){
    return parseFileHeaders();
  }

  private Packet readPacket(){

    Packet packet = new Packet();

    packet.setPacketHeaders(parsePacketHeaders());
    packet.setPacketData(parsePacketData(packet.getPacketSize()));

    return packet;
  }

  public ArrayList<Packet> getPacketList(){
    ArrayList<Packet> packetList = new ArrayList<Packet>();

    while(fileCursor < hexBuff.length){
      packetList.add(readPacket());
    }
    return packetList;
  }

  private static String reverseHexWord(String[] word) {
      String[] reverseWord = new String[word.length];
      int i = word.length -1;

      for (String string : word) {
          reverseWord[i] = string;
          i--;
      }

      return String.join("", reverseWord);
  }

  private Map<String, Object> parseFileHeaders(){

    Map<String, Object> headers = new Hashtable<String, Object>();

    try {

      headers.put("magic_number", "0x"+String.join("", new String[] {hexBuff[0], hexBuff[1], hexBuff[2], hexBuff[3]}));
      headers.put("version_major", reverseHexWord(new String[] {hexBuff[4], hexBuff[5]}));
      headers.put("version_minor", reverseHexWord(new String[] {hexBuff[6], hexBuff[7]}));
      headers.put("thiszone", reverseHexWord(new String[] {hexBuff[8], hexBuff[9], hexBuff[10], hexBuff[11]}));
      headers.put("sigfigs", reverseHexWord(new String[] {hexBuff[12], hexBuff[13], hexBuff[14], hexBuff[15]}));
      headers.put("snaplen", Integer.parseInt(reverseHexWord(new String[] {hexBuff[16], hexBuff[17], hexBuff[18], hexBuff[19]}), 16));
      headers.put("network", reverseHexWord(new String[] {hexBuff[20], hexBuff[21], hexBuff[22], hexBuff[23]}).substring(4));
      
      switch ((String )headers.get("network")) {
        case "0001":
          headers.put("networkLength", "06");
          break;
      
        default:
          headers.put("networkLength", "00");
          break;
      }

      // WTF pq ma machine lit en big endian
      System.out.println("snaplen : "+"0x"+String.join("", new String[] {hexBuff[16], hexBuff[17], hexBuff[18], hexBuff[19]}));
      System.out.println("snaplen : "+ Integer.parseUnsignedInt(String.join("", new String[] {hexBuff[16], hexBuff[17], hexBuff[18], hexBuff[19]}), 16));

      // System.out.println("version_major : "+headers.get("version_major"));
      // System.out.println("version_minor : "+headers.get("version_minor"));
      // System.out.println("thiszone : "+headers.get("thiszone"));
      // System.out.println("sigfigs : "+headers.get("sigfigs"));
      // System.out.println("snaplen : "+headers.get("snaplen"));
      // System.out.println("network : "+headers.get("network"));

      this.fileCursor += 24;

    } catch (Exception e) {
        e.printStackTrace();
    }
    return headers;
  }

  private Map<String, Object> parsePacketHeaders(){
    Map<String, Object> headers = new Hashtable<String, Object>();

    //headers.put("ts_sec", reverseHexWord(new String[] {hexBuff[0], hexBuff[1], hexBuff[2], hexBuff[3]}));
    headers.put("ts_sec", Integer.parseUnsignedInt(reverseHexWord(new String[] {hexBuff[fileCursor], hexBuff[fileCursor+1], hexBuff[fileCursor+2], hexBuff[fileCursor+3]}), 16));
    headers.put("ts_usec", Integer.parseUnsignedInt(reverseHexWord(new String[] {hexBuff[fileCursor+4], hexBuff[fileCursor+5], hexBuff[fileCursor+6], hexBuff[fileCursor+7]}), 16));
    headers.put("incl_len", Integer.parseUnsignedInt(reverseHexWord(new String[] {hexBuff[fileCursor+8], hexBuff[fileCursor+9], hexBuff[fileCursor+10], hexBuff[fileCursor+11]}), 16));
    headers.put("orig_len", Integer.parseUnsignedInt(reverseHexWord(new String[] {hexBuff[fileCursor+12], hexBuff[fileCursor+13], hexBuff[fileCursor+14], hexBuff[fileCursor+15]}), 16));

    //headers.put("incl_len", String.join("", new String[] {hexBuff[8], hexBuff[9], hexBuff[10], hexBuff[11]}));
    //headers.put("orig_len", String.join("", new String[] {hexBuff[12], hexBuff[13], hexBuff[14], hexBuff[15]}));

    // System.out.println("ts_sec : "+headers.get("ts_sec"));
    // System.out.println("ts_usec : "+headers.get("ts_usec"));
    // System.out.println("incl_len : "+headers.get("incl_len"));
    // System.out.println("orig_len : "+headers.get("orig_len"));

    this.fileCursor += 16;

    return headers;
  }

  private String parsePacketData(int packetLength){

    // System.out.println(String.join("", Arrays.copyOfRange(this.hexBuff, fileCursor, fileCursor+= packetLength)));
    return String.join("", Arrays.copyOfRange(this.hexBuff, fileCursor, fileCursor+= packetLength));
  }
}
