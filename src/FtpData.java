package src;
public class FtpData {

    private String ip;
    private int port;
    private String ipClient;
    private boolean isMatched;


    public FtpData(String ip, int port, String ipClient){
        this.ip = ip;
        this.port = port;
        this.ipClient = ipClient;
        this.isMatched = true;
    }

    public FtpData(){
        this.ip = "";
        this.port = 0;
        this.isMatched = false;
    }

    public String getIp() {
        return ip;
    }

    public void setIp(String ip) {
        this.ip = ip;
    }

    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public boolean isMatched() {
        return isMatched;
    }

    public void setMatched(boolean isMatched) {
        this.isMatched = isMatched;
    }

    public String getIpClient() {
        return ipClient;
    }

    public void setIpClient(String ipClient) {
        this.ipClient = ipClient;
    }

    public String toString(){
        return "FTP DATA\n"+ipClient+" Downloading data from "+ip+":"+port;
    }

}
