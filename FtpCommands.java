public enum FtpCommands {

    USER("USER "), // <username> <CRLF>
    PASS("PASS "), //<password> <CRLF>
    ACCT("ACCT "), //<SP> <account-information> <CRLF>
    CWD("CWD "),  //<SP> <pathname> <CRLF>
    CDUP("CDUP\r\n"), //<CRLF>
    SMNT("SMNT "), //<SP> <pathname> <CRLF>
    QUIT("QUIT\r\n"), //<CRLF>
    REIN("REIN\r\n"), //<CRLF>
    PORT("PORT "), //<SP> <host-port> <CRLF>
    PASV("PASV\r\n"), //<CRLF>
    TYPE("TYPE "), //<SP> <type-code> <CRLF>
    STRU("STRU "), //<SP> <structure-code> <CRLF>
    MODE("MODE "), //<SP> <mode-code> <CRLF>
    RETR("RETR "), //<SP> <pathname> <CRLF>
    STOR("STOR "), //<SP> <pathname> <CRLF>
    STOU("STOU\r\n"), //<CRLF>
    APPE("APPE "), //<SP> <pathname> <CRLF>
    ALLO("ALLO "), //<SP> <decimal-integer>
        //[<SP> R <SP> <decimal-integer>] <CRLF>
    REST("REST "), //<SP> <marker> <CRLF>
    RNFR("RNFR "), //<SP> <pathname> <CRLF>
    RNTO("RNTO "), //<SP> <pathname> <CRLF>
    ABOR("ABOR\r\n"), //<CRLF>
    DELE("DELE "), //<SP> <pathname> <CRLF>
    RMD("RMD "),  //<SP> <pathname> <CRLF>
    MKD("MKD "),  //<SP> <pathname> <CRLF>
    PWD("PWD\r\n"),  //<CRLF>
    LIST("LIST "), //[<SP> <pathname>] <CRLF>
    NLST("NLST "), //[<SP> <pathname>] <CRLF>
    SITE("SITE "),//<SP> <string> <CRLF>
    SYST("SYST\r\n"), //<CRLF>
    STAT("STAT "), //[<SP> <pathname>] <CRLF>
    HELP("HELP "), //[<SP> <string>] <CRLF>
    NOOP("NOOP\r\n"); //<CRLF>

    private final String pattern;

    FtpCommands(String p){
        this.pattern = p;
    }

    public String toString(){
        return pattern;
    }

    
}
