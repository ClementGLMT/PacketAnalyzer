public class Tcp {

    private int sourcePort;
    private int destinationPort;
    private long sequenceNumber;
    private long acknowlegmentNumber;
    private int headerLength;
    private String flags;
    private int CWR;
    private int ECN;
    private int urgent;
    private int ack;
    private int push;
    private int reset;
    private int syn;
    private int fin;
    private String window;
    private String checksum;
    private String urgentPointer;
    private String options;
    private String payload;
    private String headers;
    private boolean isMatched;

    public Tcp(int sourcePort, int destinationPort, long sequenceNumber, long acknowlegmentNumber, int headerLength, String flags, String window, String checksum, String urgentPointer, String options, String payload, String headers){
        
        this.sourcePort = sourcePort;
        this.destinationPort = destinationPort;
        this.sequenceNumber = sequenceNumber;
        this.acknowlegmentNumber = acknowlegmentNumber;
        this.headerLength = headerLength;
        this.flags = ProtocolParser.addFlagsPadding(Integer.toBinaryString(Integer.parseInt(flags, 16)), 8);
        resolveFlags(this.flags);
        this.window = window;
        this.checksum = checksum;
        this.urgentPointer = urgentPointer;
        this.options = options;
        this.payload = payload;
        this.headers = headers;
        this.isMatched = true;

    }

    public Tcp(int sourcePort, int destinationPort, long sequenceNumber, long acknowlegmentNumber, int headerLength, String flags, String window, String checksum, String urgentPointer, String payload, String headers){
        
        this.sourcePort = sourcePort;
        this.destinationPort = destinationPort;
        this.sequenceNumber = sequenceNumber;
        this.acknowlegmentNumber = acknowlegmentNumber;
        this.headerLength = headerLength;
        this.flags = flags;
        this.window = window;
        this.checksum = checksum;
        this.options = "";
        this.urgentPointer = urgentPointer;
        this.payload = payload;
        this.headers = headers;
        this.isMatched = true;

    }

    public Tcp(){
        this.sourcePort = 0;
        this.destinationPort = 0;
        this.sequenceNumber = 0;
        this.acknowlegmentNumber = 0;
        this.headerLength = 0;
        this.flags = "";
        this.window = "";
        this.checksum = "";
        this.urgentPointer = "";
        this.options = "";
        this.payload = "";
        this.isMatched = false;
    }

    public boolean isMatched(){
        return isMatched;
    }

    public String getPayload(){
        return payload;
    }

    public int getHeaderLengthBytes(){
        return headerLength*4;
    }

    public String getHeaders(){
        return headers;
    }

    public int getCWR(){
        return CWR;
    }

    public int getECN(){
        return ECN;
    }
    public int getUrgent(){
        return urgent;
    }
    public int getAck(){
        return ack;
    }
    public int getPush(){
        return push;
    }
    public int getReset(){
        return reset;
    }
    public int getSyn(){
        return syn;
    }
    public int getFin(){
        return fin;
    }
    public int getSourcePort(){
        return sourcePort;
    }
    public int getDestinationPort(){
        return destinationPort;
    }

    private void resolveFlags(String myFlags){

       CWR = Character.getNumericValue(myFlags.charAt(0));
       ECN = Character.getNumericValue(myFlags.charAt(1));
       urgent = Character.getNumericValue(myFlags.charAt(2));
       ack = Character.getNumericValue(myFlags.charAt(3));
       push = Character.getNumericValue(myFlags.charAt(4));
       reset = Character.getNumericValue(myFlags.charAt(5));
       syn = Character.getNumericValue(myFlags.charAt(6));
       fin = Character.getNumericValue(myFlags.charAt(7));

    }

    private String flagsToString(){
        String fl = "";

        if(CWR == 1){
            fl += "[Congestion Window Reduced]  ";
        }
        if(ECN == 1){
            fl += "[ECN-Echo]  ";
        }
        if(urgent == 1){
            fl += "[Urgent]  ";
        }
        if(ack == 1){
            fl += "[Acknowledgment]  ";
        }
        if(push == 1){
            fl += "[Push]  ";
        }
        if(reset == 1){
            fl += "[Reset]  ";
        }
        if(syn == 1){
            fl += "[Syn]  ";
        }
        if(fin == 1){
            fl += "[Fin]  ";
        }

        return fl;

    }

    public String toString(){
        return "TCP "+flagsToString();
        // return "------TCP------\nFlags : "+flagsToString()+"\nPORTS : "+sourcePort+" ----> "+destinationPort;
        // return "------TCP------\nSource port : "+sourcePort+"\nDestination port : "+destinationPort+"\nSequence number : "+sequenceNumber+"\nAcknowledgment number : "+acknowlegmentNumber+"\nHeader length : "+headerLength+" ("+getHeaderLengthBytes()+")\nFlags : "+flags+" "+flagsToString()+"\nWindow : "+window+"\nChecksum : "+checksum+"\nUrgent Pointer : "+urgentPointer+"\nOptions : "+options;
    }
    
}
