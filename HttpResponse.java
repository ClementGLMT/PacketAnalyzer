import java.util.Hashtable;
import java.util.Map;

public class HttpResponse {

    private int responseCode;
    private String responseMsg;
    private boolean isMatched;
    private String httpData;
    private String httpHeaders;
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
        return httpData;
    }

    public HttpResponse(int responseCode, String responseMsg, String httpData){
        this.responseCode = responseCode;
        this.responseMsg = responseMsg;
        this.httpData = httpData;
        this.httpHeaders = httpData.substring(0, httpData.indexOf("\r\n\r\n")+4);
        this.headers = new Hashtable<String, String>();
        parseHeaders(this.httpHeaders);
        this.isMatched = true;
    }

    public HttpResponse(){
        this.responseCode = 0;
        this.responseMsg = "";
        this.httpData = "";
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
        return "------HTTP------\nResponse code : "+responseCode+"\nResponse reason : "+responseMsg+headersToString();
    }
    
}
