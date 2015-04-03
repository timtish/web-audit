package ru.timtish.security.web.audit.custom;

import ru.timtish.security.web.audit.AuditContextService;
import ru.timtish.security.web.audit.ContextHolder;

import java.io.IOException;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

/**
 * Логирование начала и окончания сессии с автоматической установкой полученного имени залогиненого пользователя в атрибут сессии.
 */
public class AuditLoginServletFilter implements Filter {
    public AuditLoginServletFilter() {
    }

    public void init(FilterConfig config) throws ServletException {
    }

    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest)request;
        String userName = AuditContextService.getAuthUserName(req);
        AuditContextService auditContext = AuditContextService.get();
        chain.doFilter(request, response);
        String newUserName = AuditContextService.getAuthUserName(req);
        if(userName == null) {
            if(newUserName != null) {
                ContextHolder contextHolder = auditContext.getContextHolder();
                if (contextHolder instanceof SessionAttributeContextHelper) {
                    ((SessionAttributeContextHelper) contextHolder).setAuthUserName(req, newUserName);
                }
                auditContext.login(newUserName, req.getRemoteAddr());
            }
        } else if(newUserName == null) {
            auditContext.init(userName, req.getRemoteAddr());
            auditContext.logout();
            ContextHolder contextHolder = auditContext.getContextHolder();
            if (contextHolder instanceof SessionAttributeContextHelper) {
                ((SessionAttributeContextHelper) contextHolder).setAuthUserName(req, null);
            }
        }

    }

    public void destroy() {
    }
}
