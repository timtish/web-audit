package ru.timtish.security.web.audit;

/**
 * Объект логируемого события.
 */
public class AuditEvent {

    final private String action;

    final private String message;

    public AuditEvent(String action, String message) {
        this.action = action;
        this.message = message;
    }

    public String getAction() {
        return action;
    }

    public String getMessage() {
        return message;
    }

}
