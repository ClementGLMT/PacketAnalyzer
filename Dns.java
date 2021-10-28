import java.util.ArrayList;
import java.util.Hashtable;

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

    private ArrayList<DnsQuery> dnsQueries;
    private ArrayList<DnsResponse> dnsResponses;

    private int cursor;

    private boolean finished;

    private Hashtable<Integer, String> offsetBank;

    
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
        this.cursor = 0;
        this.finished = false;
        this.offsetBank = new Hashtable<Integer, String>();
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

        this.dnsQueries = new ArrayList<DnsQuery>();
        this.dnsResponses = new ArrayList<DnsResponse>();

        parseDnsData();
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
        return ""+getQueryOrResponse()+"\nTransaction ID : "+Integer.parseInt(transactionId, 16)+/*"\nFlags : "+flags+*/"\nQuestions : "+Integer.parseInt(questions, 16)+"\nAnswerRRs : "+Integer.parseInt(answerRRs, 16)+"\nAuthority RRs : "+Integer.parseInt(authorityRRs, 16)+"\nAdditional RRs : "+Integer.parseInt(additionalRRs, 16)+getQuestions()+getAnswers();
        // return "------DNS------\nType : "+getQueryOrResponse()+"\nTransaction ID : "+transactionId+/*"\nFlags : "+flags+*/"\nQuestions : "+questions+"\nAnswerRRs : "+answerRRs+"\nAuthority RRs : "+authorityRRs+"\nAdditional RRs : "+additionalRRs+getQuestions()+getAnswers();
    }

    public String getQuestions(){
        String r="";
        for (int i=0; i < dnsQueries.size(); i++) {
            r += "\n\nQUESTIONS : \nQuestion "+(i+1)+"\n\tName : "+dnsQueries.get(i).getName()+"\n\tType : "+dnsQueries.get(i).getTypeHuman()+"\n\tClass : "+dnsQueries.get(i).getDnsClassHuman();
        }
        return r;
    }

    public String getAnswers(){
        String r="";
        for(int i=0; i < dnsResponses.size(); i++){
            r += "\n\nANSWERS : \nAnswer "+(i+1)+"\n\tName : "+dnsResponses.get(i).getName()+"\n\tType : "+dnsResponses.get(i).getTypeHuman()+"\n\tClass : "+dnsResponses.get(i).getDnsClassHuman()+"\n\tTTL : "+dnsResponses.get(i).getTtl()+"\n\tResponse Length : "+dnsResponses.get(i).getDataLength()+"\n\tResponse : "+dnsResponses.get(i).getAddress();
        }
        return r;
    }

    public boolean isMatched(){
        return isMatched;
    }

    public String getDnsData(){
        return dnsData;
    }

    private String readDomain(){
        String finalDomain = "";
        String domain;

        finished = false;

        // System.out.println("Data from readDomain : "+dnsData.substring(cursor));

        while(!((domain = readWord(dnsData.substring(cursor))).equals("") || finished)){
            finalDomain += domain;
        }
        if(finished){
            finalDomain += domain;
        }
        return finalDomain.substring(0, finalDomain.length()-1);

    }

    private String readDomainAnswer(int dataLength, int type){
        String finalDomain = "";
        String domain;
        String len;
        int pointer;
        int max = cursor + dataLength*2;

        String answer = dnsData.substring(cursor, max);

        // System.out.println("Answer : "+answer);

        // A
        if(type == 1){
            return ProtocolParser.ipv4HexaToHuman(answer);
        }

        // AAA
        if(type == 28){
            return answer.substring(0, 4)+":"+answer.substring(4, 8)+":"+answer.substring(8, 12)+":"+answer.substring(12, 16)+":"+answer.substring(16, 20)+":"+answer.substring(20, 24)+":"+answer.substring(24, 28)+":"+answer.substring(28, 32);
        }

        // CNAME
        if(type == 5){
            String answer2 = readNameWithOffsets(answer);
            return answer2.substring(0, answer2.length()-1);
        }

        // NS
        if(type == 2){
            String answer2 = readNameWithOffsets(answer);
            return answer2.substring(0, answer2.length()-1);
        }

        // MX
        if(type == 15){
            answer = answer.substring(4);
            cursor += 4;
            String answer2 = readNameWithOffsets(answer);
            return answer2.substring(0, answer2.length()-1);
        }

        // while(cursor < max){

        //     finished = false;

        //     while(!((domain = readWord(""+dnsData.substring(cursor))).equals("") || finished)){
        //         finalDomain += domain;
        //         System.out.println("Final DOmain dans while : "+finalDomain);
        //     }
        //     if(finished){
        //         finalDomain += domain;
        //         System.out.println("Final DOmain dans if : "+finalDomain);

        //     }
        // }

        // System.out.println("Final Domain Return : "+finalDomain);

        return finalDomain;
    }

    public String readWord(String data){

        String len;
        int intlen;
        String word = "";
        finished = false;
        int pointer;
        int pointer2;
        String intlen2;
        len = Integer.toBinaryString(Integer.parseInt(data.substring(0, 1), 16));


        // If we have an offset
        if(len.startsWith("11")){
            // System.out.println("Data : "+data);
            pointer = Integer.parseInt( ProtocolParser.addFlagsPadding(Integer.toBinaryString(Integer.parseInt(data.substring(0, 4), 16)), 16).substring(2, 16), 2);
            int offset = pointer;
            pointer = pointer*2 - 24;
            // System.out.println("Pointer : "+pointer);
            // System.out.println("Len : "+ ProtocolParser.addFlagsPadding(Integer.toBinaryString(Integer.parseInt(dnsData.substring(pointer, pointer+2), 16)), 16));
            // System.out.println("Dns Data at pointer : "+dnsData.substring(pointer, pointer+6));
            
            while((intlen = Integer.parseInt(ProtocolParser.addFlagsPadding(Integer.toBinaryString(Integer.parseInt(dnsData.substring(pointer, pointer+2), 16)), 16), 2)) != 0){
                // if((intlen2 = ProtocolParser.addFlagsPadding(Integer.toBinaryString(Integer.parseInt(data.substring(pointer, pointer+4), 16)), 16)).startsWith("11")){
                //     pointer2 = Integer.parseInt(ProtocolParser.addFlagsPadding(intlen2, 16).substring(2, 16), 2);
                //     pointer2 = pointer2*2 - 24;
                //     // while((intlen = Integer.parseInt(ProtocolParser.addFlagsPadding(Integer.toBinaryString(Integer.parseInt(dnsData.substring(pointer2, pointer2+2), 16)), 16), 2)) != 0){
                //     //     String domain = ProtocolParser.domainHexaToHuman(dnsData.substring(pointer2+2, pointer2+2+intlen*2));
                //     //     System.out.println("Domain : "+domain);
                //     //     word += domain + ".";
                //     //     pointer2 += 2+intlen*2;
                //     // }
                // } else {
                // System.out.println("intlen : "+intlen);
                String domain = ProtocolParser.hexaToAscii(dnsData.substring(pointer+2, pointer+2+intlen*2));
                // System.out.println("Domain : "+domain);
                word += domain + ".";
                pointer += 2+intlen*2;
                // System.out.println("Word in while : "+word);
                // }
            }

            // System.out.println("Word : "+word);
            offsetBank.put(offset, word.substring(0, word.length()-1));
            cursor += 2;
            finished = true;

        } else if((intlen = Integer.parseInt(data.substring(0, 2), 16)) != 0){
            // If we have a word
            // System.out.println("intlen = "+intlen);
            String domain = ProtocolParser.hexaToAscii(dnsData.substring(cursor+2, cursor+2+intlen*2));
            word += domain + ".";
            cursor += 2+intlen*2;
        }
        // System.out.println("Returned word : "+word);
        // System.out.println("Finished : "+finished);
        return word;
    }

    // public String[] readOneWord(String data, int offset){

    //     String len = Integer.toBinaryString(Integer.parseInt(data.substring(0, 1), 16));
    //     int intlen;

    //     if(len.startsWith("11")){

    //     } else {
    //         while()
    //     }


    // }

    public String readNameWithOffsets(String data){
        // System.out.println("Data in readNameOffsets : "+data);

        String len = Integer.toBinaryString(Integer.parseInt(data.substring(0, 1), 16));
        int pointer;
        int intlen;
        String word="";

        if(len.startsWith("11")){

            // System.out.println("Data in readNameOffsets : "+data);

            // Pointer where data to read starts
            pointer = Integer.parseInt(ProtocolParser.addFlagsPadding(Integer.toBinaryString(Integer.parseInt(data.substring(0, 4), 16)), 16).substring(2, 16), 2);
            pointer = pointer*2 - 24;

            // Getting len as integer
            len = Integer.toBinaryString(Integer.parseInt(dnsData.substring(pointer, pointer+1), 16));
            intlen = Integer.parseInt(ProtocolParser.addFlagsPadding(Integer.toBinaryString(Integer.parseInt(dnsData.substring(pointer, pointer+2), 16)), 16), 2);
            // System.out.println("intlen on : "+dnsData.substring(pointer, pointer+2));

            // System.out.println("intlen : "+intlen);
            // System.out.println("DOmain on : "+dnsData.substring(pointer+2, pointer+2+intlen*2));

            while(intlen != 0 && !len.startsWith("11")){
                String domain = ProtocolParser.hexaToAscii(dnsData.substring(pointer+2, pointer+2+intlen*2));
                // System.out.println("Domain : "+domain);
                word += domain + ".";
                pointer += 2+intlen*2;

                len = Integer.toBinaryString(Integer.parseInt(dnsData.substring(pointer, pointer+1), 16));
                intlen = Integer.parseInt(ProtocolParser.addFlagsPadding(Integer.toBinaryString(Integer.parseInt(dnsData.substring(pointer, pointer+2), 16)), 16), 2);
                // System.out.println("Len : "+len);
                // System.out.println("intLen end while : "+intlen);
                // System.out.println("Working on : "+dnsData.substring(pointer, pointer+2));


            }
            if(intlen == 0){
                finished = true;
                cursor += 4;
            } else {
                word += readNameWithOffsets(dnsData.substring(pointer));
            }

        } else {

            intlen = Integer.parseInt(data.substring(0, 2), 16);

            while(intlen != 0 && !len.startsWith("11")){
                String domain = ProtocolParser.hexaToAscii(dnsData.substring(cursor+2, cursor+2+intlen*2));
                word += domain + ".";
                cursor += 2+intlen*2;

                len = Integer.toBinaryString(Integer.parseInt(dnsData.substring(cursor, cursor+1), 16));
                intlen = Integer.parseInt(ProtocolParser.addFlagsPadding(Integer.toBinaryString(Integer.parseInt(dnsData.substring(cursor, cursor+2), 16)), 16), 2);
            }
            if(intlen == 0){
                finished = true;
                cursor += 2;

            } else {
                word += readNameWithOffsets(dnsData.substring(cursor));
            }
        }
        // System.out.println("Word : "+word);
        return word;

    }

    public void parseDnsData(){
        int i;
        cursor = 0;

        for(i=0 ; i < Integer.parseInt(questions, 16); i++){
            DnsQuery query = new DnsQuery();

            // Get name field
            query.setName(readDomain());

            // System.out.println("Name : "+query.getName());

            // Get Type fields
            query.setType(Integer.parseInt(dnsData.substring(cursor+2, cursor+6), 16));

            // Get Class field
            query.setDnsClass(Integer.parseInt(dnsData.substring(cursor+6, cursor+10), 16));
            dnsQueries.add(query);
            cursor += 10;
        }

        // cursor += 2;

        for(i=0 ; i < Integer.parseInt(answerRRs, 16); i++){
            DnsResponse answer = new DnsResponse();

            // System.out.println("From cursor : "+dnsData.substring(cursor));



            int type = Integer.parseInt(dnsData.substring(cursor+4, cursor+8), 16);

            // System.out.println("Type of answer "+(i+1)+": "+type);

            if(type == 1 || type == 2 || type == 15 || type == 28 || type == 5){

                // Get name field
                String name = readNameWithOffsets(dnsData.substring(cursor));
                answer.setName(name.substring(0, name.length()-1));
                // answer.setName(readDomain());
                // cursor += 2;

                // System.out.println("Domain queried : "+answer.getName());

                // System.out.println("From cursor : "+dnsData.substring(cursor));

                // Get Type fields
                // System.out.println("Type : "+dnsData.substring(cursor, cursor+4));

                answer.setType(Integer.parseInt(dnsData.substring(cursor, cursor+4), 16));

                // Get Class field
                answer.setDnsClass(Integer.parseInt(dnsData.substring(cursor+4, cursor+8), 16));

                answer.setTtl(Integer.parseInt(dnsData.substring(cursor+8, cursor+16), 16));

                answer.setDataLength(Integer.parseInt(dnsData.substring(cursor+16, cursor+=20), 16));

                // System.out.println("Data lenth : "+answer.getDataLength());

                String domainAnswer = readDomainAnswer(answer.getDataLength(), type);

                answer.setAddress(domainAnswer);

                dnsResponses.add(answer);

                // cursor += 2;

                // System.out.println("Added answer : "+answer.getAddress());

                // System.out.println("Cursor position : "+dnsData.substring(cursor));
            } else {
                cursor += 4 + 4 + 4 + 8;
                cursor += Integer.parseInt(dnsData.substring(cursor, cursor+4), 16)*2;

                cursor += 4;
            }

        }

    }
}
