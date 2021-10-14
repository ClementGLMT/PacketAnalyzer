public class Tcp {

    private int sourcePort;
    private int destinationPort;
    private long sequenceNumber;
    private long acknowlegmentNumber;
    private int headerLength;
    private String flags;
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
        this.flags = flags;
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

    public boolean getIsMatched(){
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

    public String toString(){
        return "------TCP------\nSource port : "+sourcePort+"\nDestination port : "+destinationPort+"\nSequence number : "+sequenceNumber+"\nAcknowledgment number : "+acknowlegmentNumber+"\nHeader length : "+headerLength+" ("+getHeaderLengthBytes()+")\nFlags : "+flags+"\nWindow : "+window+"\nChecksum : "+checksum+"\nUrgent Pointer : "+urgentPointer+"\nOptions : "+options;
    }
    
}
