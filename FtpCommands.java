public enum FtpCommands {

    USER("USER ", "USER"), // <username> <CRLF>
    PASS("PASS ", "PASS"), //<password> <CRLF>
    ACCT("ACCT ", "ACCT"), //<SP> <account-information> <CRLF>
    CWD("CWD ", "CWD"),  //<SP> <pathname> <CRLF>
    CLNT("CLNT ", "CLNT"),
    CDUP("CDUP", "CDUP"), //<CRLF>
    SMNT("SMNT ", "SMNT"), //<SP> <pathname> <CRLF>
    QUIT("QUIT", "QUIT"), //<CRLF>
    REIN("REIN", "REIN"), //<CRLF>
    PORT("PORT ", "PORT"), //<SP> <host-port> <CRLF>
    PASV("PASV", "PASV"), //<CRLF>
    TYPE("TYPE ", "TYPE"), //<SP> <type-code> <CRLF>
    STRU("STRU ", "STRU"), //<SP> <structure-code> <CRLF>
    MODE("MODE ", "MODE"), //<SP> <mode-code> <CRLF>
    RETR("RETR ", "RETR"), //<SP> <pathname> <CRLF>
    STOR("STOR ", "STOR"), //<SP> <pathname> <CRLF>
    STOU("STOU", "STOU"), //<CRLF>
    APPE("APPE ", "APPE"), //<SP> <pathname> <CRLF>
    ALLO("ALLO ", "ALLO"), //<SP> <decimal-integer>
        //[<SP> R <SP> <decimal-integer>] <CRLF>
    REST("REST ", "REST"), //<SP> <marker> <CRLF>
    RNFR("RNFR ", "RNFR"), //<SP> <pathname> <CRLF>
    RNTO("RNTO ", "RNTO"), //<SP> <pathname> <CRLF>
    ABOR("ABOR", "ABOR"), //<CRLF>
    DELE("DELE ", "DELE"), //<SP> <pathname> <CRLF>
    RMD("RMD ", "RMD"),  //<SP> <pathname> <CRLF>
    MKD("MKD ", "MKD"),  //<SP> <pathname> <CRLF>
    PWD("PWD", "PWD"),  //<CRLF>
    LIST("LIST ", "LIST"), //[<SP> <pathname>] <CRLF>
    NLST("NLST ", "NLST"), //[<SP> <pathname>] <CRLF>
    SITE("SITE ", "SITE"),//<SP> <string> <CRLF>
    SIZE("SIZE ", "SIZE"),
    SYST("SYST", "SYST"), //<CRLF>
    STAT("STAT ", "STAT"), //[<SP> <pathname>] <CRLF>
    HELP("HELP ", "HELP"), //[<SP> <string>] <CRLF>
    FEAT("FEAT", "FEAT"),
    NOOP("NOOP", "NOOP"); //<CRLF>

    private final String pattern;
    private final String name;

    FtpCommands(String p, String n){
        this.pattern = p;
        this.name = n;
    }

    public String toString(){
        return pattern;
    }

    public String getName(){
        return name;
    }

    
}
