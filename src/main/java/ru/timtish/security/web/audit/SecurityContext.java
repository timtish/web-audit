package ru.timtish.security.web.audit;

public class SecurityContext {

    private String ip;

    private String userName;

    public SecurityContext() {
    }

    public SecurityContext(String userName) {
        this.userName = userName;
    }

    public SecurityContext(String userName, String ip) {
        this.userName = userName;
        this.ip = ip;
    }

    public String getIp() {
        return ip;
    }

    public void setIp(String ip) {
        this.ip = ip;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }
}
