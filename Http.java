public class Http {

    private String method;
    private String uri;
    // private String version;
    private String httpData;
    private boolean isMatched;

    public Http(String method, String uri/*, String version*/, String httpData){
        this.method = method;
        this.uri = uri;
        this.httpData = httpData;
        isMatched = true;
    }

    public Http(){
        this.method = "";
        this.uri = "";
        this.httpData = "";
        isMatched = false;
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

    
}
