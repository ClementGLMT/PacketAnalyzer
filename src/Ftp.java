package src;
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
        String r = "";
        String r2 = "";

        if(responseCode == 227){
            FtpData ftpData = ProtocolParser.getFtpPassiveInfo(arg, "");
            r2 += "Entering passive mode : Download at "+ftpData.getIp()+":"+ftpData.getPort();
        }

        if(responseCode == 0){
            r += "FTP Command\n"+command+(arg.equals("") ? "" : " : "+arg);
        } else {
            r += "FTP Response\n"+responseCode+(arg.equals("") ? "" : " : "+(r2.equals("") ? ""+arg : r2));
        }

        return r;
    }
}
