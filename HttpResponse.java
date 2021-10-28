import java.util.Hashtable;
import java.util.Map;

public class HttpResponse {

    private int responseCode;
    private String responseMsg;
    private boolean isMatched;
    private String httpPacket;
    private String httpHeaders;
    private String httpData;
    private Hashtable<String, String> headers;

    public int getResponseCode() {
        return responseCode;
    }

    public void setResponseCode(int responseCode) {
        this.responseCode = responseCode;
    }

    public String getResponseMsg() {
        return responseMsg;
    }

    public void setResponseMsg(String responseMsg) {
        this.responseMsg = responseMsg;
    }

    public boolean isMatched() {
        return isMatched;
    }

    public void setMatched(boolean isMatched) {
        this.isMatched = isMatched;
    }

    public String getHttpData(){
        return httpPacket;
    }

    public HttpResponse(int responseCode, String responseMsg, String httpPacket){
        this.responseCode = responseCode;
        this.responseMsg = responseMsg;
        this.httpPacket = httpPacket;
        this.httpHeaders = httpPacket.substring(0, httpPacket.indexOf("\r\n\r\n")+4);
        this.headers = new Hashtable<String, String>();
        parseHeaders(this.httpHeaders);
        this.httpData = httpPacket.substring(httpPacket.indexOf("\r\n\r\n")+4);
        this.isMatched = true;
    }

    public HttpResponse(){
        this.responseCode = 0;
        this.responseMsg = "";
        this.httpPacket = "";
        this.isMatched = false;
    }

    public void parseHeaders(String headersString){
        for (String header : headersString.split("\r\n")) {
            headers.put(header.split(":")[0].trim(), header.split(":")[1].trim());
        }
    }

    public String headersToString(){
        String r = "\nHeaders :\n";
        for (Map.Entry<String,String> h : headers.entrySet()) {
            r += "\n\t"+h.getKey()+": "+h.getValue();
        }
        return r;
    }

    public String toString(){
        return "HTTP Response : "+responseCode+" - "+responseMsg+headersToString()+(httpData.equals("") ? "" : "\n\nData : \n\n"+httpData);
        // return "------HTTP------\nResponse code : "+responseCode+"\nResponse reason : "+responseMsg+headersToString()+"\nHTTP Response data : \n"+httpData;
    }
    
}
