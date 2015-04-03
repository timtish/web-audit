package ru.timtish.security.web.audit.j2ee;

import ru.timtish.security.web.audit.AuditContextService;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

/**
 * Логирование начала и окончания сессии.
 *
 * filter-mapping должен быть на login и logout страницы.
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
        AuditContextService auditContext = AuditContextService.get();

        // run chain process
        chain.doFilter(request, response);

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

        // todo: audit login exception and 403
    }

    @Override
    public void destroy() {
    }
}

