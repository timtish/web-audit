package ru.timtish.security.web.audit.spring;

import ru.timtish.security.web.audit.AuditContextService;
import ru.timtish.security.web.audit.AuditEvent;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.*;

/**
 * Логирование url и параметров запросов.
 */
public class AuditRequestServletFilter implements Filter {

    public AuditRequestServletFilter() {
    }

    public void init(FilterConfig config) throws ServletException {
    }

    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException
    {
        HttpServletRequest req = (HttpServletRequest) request;

        // set current thread user session
        String userName = AuditContextService.getAuthUserName(req);
        /*if (userName == null && req.getRequestURI().toLowerCase().contains("login")) {
            userName = req.getParameter("j_username");
            if (userName == null) userName = req.getParameter("username");
        }*/
        AuditContextService.get().init(userName, req.getRemoteAddr());

        // request parameters audit
        //if (auditAction(request)) {  //журналируем всё
        String parameters = "";
        Enumeration<String> paramNames = request.getParameterNames();
        while (paramNames.hasMoreElements()) {
            String paramName = paramNames.nextElement();
            if (!paramName.toLowerCase().contains("password")) {
                parameters += paramName + ":" + request.getParameter(paramName) + "\t";
            }
        }
        AuditContextService.get().event(new AuditEvent(req.getRequestURI(), parameters.isEmpty() ? "" : "parameters:\n" + parameters));

        // run chain process
        chain.doFilter(request, response);
    }

    @Override
    public void destroy() {
    }
}

