public class Dns {

    private String transactionId;
    private String flags;
    private String questions;
    private String answerRRs;
    private String authorityRRs;
    private String additionalRRs;
    private String dnsData;
    private boolean isMatched;
    
    private int fresponse;
    private int fopcode;
    private int ftruncated;
    private int frecursiondesired;
    private int fz;
    private int fad;
    private int fnonauthdata;

    private int fauthoritativeserver;
    private int frecursionavailable;
    private int fanswerauth;
    private int freplycode;

    private DnsQuery[] dnsQueries;
    private DnsResponse[] dnsResponses;

    
    public Dns(String transactionId, int flags, String question, String answerRRs, String authorityRRs, String additionalRRs, String dnsData){
        
        this.transactionId = transactionId;
        this.flags = ProtocolParser.addFlagsPadding(Integer.toBinaryString(flags), 16);
        this.questions = question;
        this.answerRRs = answerRRs;
        this.authorityRRs = authorityRRs;
        this.additionalRRs = additionalRRs;
        this.dnsData = dnsData;

        this.fresponse = Character.getNumericValue(this.flags.charAt(0));
        this.fopcode = Integer.parseInt(this.flags.substring(1, 5));
        this.fauthoritativeserver = Character.getNumericValue(this.flags.charAt(5));
        this.ftruncated = Character.getNumericValue(this.flags.charAt(6));
        this.frecursiondesired = Character.getNumericValue(this.flags.charAt(7));
        this.frecursionavailable = Character.getNumericValue(this.flags.charAt(8));
        this.fz = Character.getNumericValue(this.flags.charAt(9));
        this.fnonauthdata = Character.getNumericValue(this.flags.charAt(11));
        this.freplycode = Integer.parseInt(this.flags.substring(12, 16));
        this.isMatched = true;
        
        switch (fresponse) {
            case 0:
                this.fad = Character.getNumericValue(this.flags.charAt(10));
                this.fanswerauth = 0;
                break;

            case 1:
                this.fanswerauth = Character.getNumericValue(this.flags.charAt(10));
                this.fad = 0;
                break;
         
            default:
                this.fad = 0;
                this.fanswerauth = 0;
                break;
        }
    }

    public Dns(){
        this.transactionId = "";
        this.flags = "";
        this.questions = "";
        this.answerRRs = "";
        this.authorityRRs = "";
        this.additionalRRs = "";
        this.dnsData = "";

        this.fresponse = 0;
        this.fopcode = 0;
        this.fauthoritativeserver = 0;
        this.ftruncated = 0;
        this.frecursiondesired = 0;
        this.frecursionavailable = 0;
        this.fz = 0;
        this.fnonauthdata = 0;
        this.freplycode = 0;
        this.isMatched = false;
    }

    public String getQueryOrResponse(){
        return (fresponse == 0) ? "DNS Query" : "DNS Response"; 
    }

    public String toString(){
        return "------DNS------\nType : "+getQueryOrResponse()+"\nTransaction ID : "+transactionId+"\nFlags : "+flags+"\nQuestion : "+questions+"\nAnswerRRs : "+answerRRs+"\nAuthority RRs : "+authorityRRs+"\nAdditional RRs : "+additionalRRs;
    }

    public boolean getIsMatched(){
        return isMatched;
    }

    public String getDnsData(){
        return dnsData;
    }

    // LA CEST LE BORDEL
    public void parseDnsData(){
        int i,j=0;
        String len;
        for(i=0 ; i < Integer.parseInt(questions); i++){
            DnsQuery query = new DnsQuery();
            while(!(len = dnsData.substring(j, j+2)).equals("00")){

                System.out.println("len="+len+"|");
                int intlen = Integer.parseInt(len, 16);
                System.out.println("intlen="+intlen);

                StringBuilder output = new StringBuilder();
                String hex = dnsData.substring(j+2, j+3+intlen*2);
                for (int k = 0; k < hex.length(); k+=2) {
                    String str = hex.substring(k, k+2);
                    output.append((char)Integer.parseInt(str, 16));
                }
                query.setName(query.getName()+output.toString()+".");
                j += 2+intlen*2;
            }
            query.setName(query.getName().substring(0, query.getName().length()-2));
            System.out.println("Domain queried : "+query.getName());
        }
    }
}
