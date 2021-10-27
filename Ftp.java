public class Ftp {

    private String command;
    private int responseCode;
    private String arg;
    private boolean isMatched;
    
    public Ftp(String command, String arg, int responseCode){
        this.command = command;
        this.arg = arg;
        this.responseCode = responseCode;
        isMatched = true;
    }

    public Ftp(){
        this.command = "";
        this.arg = "";
        this.responseCode = 0;
        isMatched = false;    
    }

    public boolean isMatched(){
        return isMatched;
    }

    public String getCommand(){
        return command;
    }

    public int getResponseCode(){
        return responseCode;
    }

    public String toString(){
        return "------FTP------\n" +((responseCode != 0) ? "Response code : "+responseCode : "Command : "+command) + "\nArg : "+arg;
    }
}
