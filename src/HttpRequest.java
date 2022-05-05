package src;
import java.util.HashMap;
import java.util.Map;

public class HttpRequest {

    private String method;
    private String uri;
    private String httpPacket;
    private String httpHeaders;
    private boolean isMatched;
    private HashMap<String, String> headers;

    public HttpRequest(String method, String uri, String httpPacket){
        this.method = method;
        this.uri = uri;
        this.httpPacket = httpPacket;
        this.httpHeaders = httpPacket.substring(0, httpPacket.indexOf("\r\n\r\n")+4);
        this.headers = new HashMap<String, String>();
        parseHeaders(this.httpHeaders);
        isMatched = true;
    }

    public HttpRequest(){
        this.method = "";
        this.uri = "";
        this.httpPacket = "";
        isMatched = false;
    }

    private void parseHeaders(String headersString){
        for (String header : headersString.split("\r\n")) {
            headers.put(header.split(":")[0].trim(), header.split(":")[1].trim());
        }
    }

    public String getMethod() {
        return method;
    }

    public void setMethod(String method) {
        this.method = method;
    }

    public String getUri() {
        return uri;
    }

    public void setUri(String uri) {
        this.uri = uri;
    }

    public String getHttpPacket() {
        return httpPacket;
    }

    public void setHttpPacket(String httpData) {
        this.httpPacket = httpData;
    }

    public boolean isMatched(){
        return isMatched;
    }

    public String headersToString(){
        String r = "\nHeaders :\n";
        for (Map.Entry<String,String> h : headers.entrySet()) {
            r += "\n\t"+h.getKey()+": "+h.getValue();
        }
        return r;
    }

    public String toString(){
        return "HTTP Request : "+method+" on "+uri+headersToString();
    }

    
}
