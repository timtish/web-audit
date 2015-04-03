package ru.timtish.security.web.audit.spring;

import ru.timtish.security.web.audit.AuditContextService;
import ru.timtish.security.web.audit.AuditEvent;
import org.springframework.security.web.WebAttributes;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.io.IOException;

/**
 * Логирование начала и окончания сессии.
 *
 * filter-mapping должен быть на login-processing-url и logout-url из спринговых настроек form-login и logout.
 */
public class AuditLoginServletFilter implements Filter {

    public AuditLoginServletFilter() {
    }

    public void init(FilterConfig config) throws ServletException {
    }

    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException
    {
        HttpServletRequest req = (HttpServletRequest) request;

        String userName = AuditContextService.getAuthUserName(req);

        // run chain process
        chain.doFilter(request, response);

        AuditContextService auditContext = AuditContextService.get();

        // audit user session update
        String newUserName = AuditContextService.getAuthUserName(req);
        if (userName == null) {
            if (newUserName != null) {
                auditContext.login(newUserName, req.getRemoteAddr());
            }
        } else {
            if (newUserName == null) {
                auditContext.init(userName, req.getRemoteAddr());
                auditContext.logout();
            }
        }

        // audit login exception (without AuthenticationFailureHandler)
        HttpSession session = req.getSession(false);
        Throwable loginError = session == null ? null : (Throwable) session.getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
        if (loginError != null) {
            String failedUserName = (String) session.getAttribute("SPRING_SECURITY_LAST_USERNAME"/*WebAttributes.LAST_USERNAME*/);
            auditContext.init(null, req.getRemoteAddr());
            auditContext.event(new AuditEvent(AuditContextService.LOGIN_FAIL, loginError.getClass().getSimpleName()
                    + " for user " + failedUserName + ": " + loginError.getLocalizedMessage()));
        }
    }

    @Override
    public void destroy() {
    }
}

