import java.util.regex.MatchResult;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ProtocolParser {

    private String packetData;
    
    public ProtocolParser(String packetData){
        this.packetData = packetData;
    }

    public boolean recognizeARP(){
        String arpPattern = "([0-9a-fA-F]{12})([0-9a-fA-F]{12})(8100[0-9a-fA-F]{4})?(0800|0806|809b|80F3|86DD)";
        String pat = "(.*)";

        // Pattern r = Pattern.compile(arpPattern);
        Pattern r = Pattern.compile(pat);

        Matcher m = r.matcher(packetData);

        System.out.println("\n"+packetData);
        System.out.println(m.results().count());

        MatchResult res = m.toMatchResult();
        System.out.println(res);
        int i = 0;
        while (m.find()) {
            for (int j = 0; j <= m.groupCount(); j++) {
                System.out.println("------------------------------------");
                System.out.println("Group " + i + ": " + m.group(j));
                i++;
             }
        }

        System.out.println(m.results());
        System.out.println(m.group(0));
        System.out.println(m.group(1));
        System.out.println(m.group(2));
        System.out.println(m.group(3));
        System.out.println(m.group(4));

        if(m.results().count() == 4){
            System.out.println(m.group(0));
            System.out.println(m.group(1));
            System.out.println(m.group(2));
            System.out.println(m.group(3));
            System.out.println(m.group(4));
            return true;
        }
        return false;
    }
}
