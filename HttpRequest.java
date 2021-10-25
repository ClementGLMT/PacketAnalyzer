import java.util.HashMap;
import java.util.Map;

public class HttpRequest {

    private String method;
    private String uri;
    // private String version;
    private String httpData;
    private String httpHeaders;
    private boolean isMatched;
    private HashMap<String, String> headers;

    public HttpRequest(String method, String uri, String httpData){
        this.method = method;
        this.uri = uri;
        this.httpData = httpData;
        this.httpHeaders = httpData.substring(0, httpData.indexOf("\r\n\r\n")+4);
        this.headers = new HashMap<String, String>();
        parseHeaders(this.httpHeaders);
        isMatched = true;
    }

    public HttpRequest(){
        this.method = "";
        this.uri = "";
        this.httpData = "";
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

    public String getHttpData() {
        return httpData;
    }

    public void setHttpData(String httpData) {
        this.httpData = httpData;
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
        return "------HTTP------\nMethod : "+method+"\nURI : "+uri+headersToString();
    }

    
}
