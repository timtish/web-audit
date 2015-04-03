package ru.timtish.security.web.audit.spring;

import ru.timtish.security.web.audit.AuditContextService;
import ru.timtish.security.web.audit.AuditEvent;
import org.springframework.security.web.savedrequest.SavedRequest;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.io.IOException;

/**
 * Логирование начала и окончания сессии.
 *
 * filter-mapping должен быть на authentication-failure-url из спринговой настройки form-login
 * (todo: предполагается что в этом адресе нет параметров, чтобы отличать от не authentication-failure событий).
 */
public class AuditUnauthorizedServletFilter implements Filter {

    public AuditUnauthorizedServletFilter() {
    }

    public void init(FilterConfig config) throws ServletException {
    }

    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException
    {
        // run chain process
        chain.doFilter(request, response);

        HttpServletRequest req = (HttpServletRequest) request;
        HttpSession session = req.getSession(false);
        if (session != null && AuditContextService.getAuthUserName(req) == null
                && req.getParameterMap().isEmpty()/* проверка что в адресе нет параметров */) {
            Object savedRequest = session.getAttribute("SPRING_SECURITY_SAVED_REQUEST"); //spring 3.1+
            if (savedRequest == null) savedRequest = session.getAttribute("SPRING_SECURITY_SAVED_REQUEST_KEY"); // spring 3.0
            if (savedRequest instanceof SavedRequest) {
                String path = ((SavedRequest) savedRequest).getRedirectUrl();
                int index = path.indexOf(req.getContextPath());
                if (index > 0) path = path.substring(index + req.getContextPath().length());
                if (!path.isEmpty() && !path.equals("/")) {
                    AuditContextService auditContext = AuditContextService.get();
                    auditContext.init(null, req.getRemoteAddr());
                    auditContext.event(new AuditEvent(AuditContextService.UNAUTHORIZED_REQUEST, "page: " + path));
                }
            }
        }
    }

    @Override
    public void destroy() {
    }
}

