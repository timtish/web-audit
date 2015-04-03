package ru.timtish.security.web.audit;

import ru.timtish.security.web.audit.j2ee.UserPrincipalContextHelper;

import javax.servlet.http.HttpServletRequest;

/**
 * Хранит контекст пользователя для целей аудита.
 */
public class AuditContextService {

    public static final String UNAUTHORIZED_REQUEST = "UNAUTHORIZED_REQUEST";
    public static final String LOGIN = "LOGIN";
    public static final String LOGIN_FAIL = "LOGIN_FAIL";
    public static final String LOGOUT = "LOGOUT";

    private EventLogger serializer = new EventLogger();
    private ContextHolder contextHolder = new UserPrincipalContextHelper();

    private static final class AuditContextHolder {
        private static final AuditContextService instance = new AuditContextService();
    }

    private ThreadLocal<SecurityContext> ctxHolder = new ThreadLocal<SecurityContext>();

    //
    public static AuditContextService get() {
        return AuditContextHolder.instance;
    }

    /**
     * Вызывается при существовании сесиии запроса
     */
    public void init(String userName, String ip) {
        ctxHolder.remove();
        ctxHolder.set(new SecurityContext(userName, ip));
    }

    /**
     * Очистка потока.
     */
    public void close() {
        ctxHolder.remove();
    }

    /**
     * Должно быть вызвано в момент LOGON
     */
    public void login(String userName, String ip) {
        init(userName, ip);
        event(new AuditEvent(LOGIN, "user log in."));
    }

    /**
     * Должно быть вызвано в момент LOGOFF
     */
    public void logout() {
        event(new AuditEvent(LOGOUT, "user log out."));
        ctxHolder.remove();
    }

    /**
     * Пишет в лог событие аудита
     */
    public void event(AuditEvent event) {
        if (event != null) {
            serializer.log(ctxHolder.get(), event);
        }
    }

    public void setSerializer(EventLogger serializer) {
        this.serializer = serializer;
    }

    public EventLogger getSerializer() {
        return serializer;
    }

    public void setContextHolder(ContextHolder contextHolder) {
        this.contextHolder = contextHolder;
    }

    public ContextHolder getContextHolder() {
        return contextHolder;
    }

    public static String getAuthUserName(HttpServletRequest req) {
        return get().contextHolder.getAuthUserName(req);
    }

}
