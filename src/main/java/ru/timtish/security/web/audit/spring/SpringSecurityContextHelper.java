package ru.timtish.security.web.audit.spring;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import ru.timtish.security.web.audit.ContextHolder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

/**
 * Получение залогиненого пользователя из spring контекста
 * (работает в том числе в фильтрах, следуюших сразу после фильтра логина в том же запросе).
 */
public class SpringSecurityContextHelper implements ContextHolder {

    public String getAuthUserName(HttpServletRequest req) {
        String userName = null;
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null) {
            HttpSession session = req.getSession(false);
            if (session != null) {
                Object sc = session.getAttribute("SPRING_SECURITY_CONTEXT"); // if context initialized in login chain
                if (sc instanceof SecurityContext) auth = ((SecurityContext) sc).getAuthentication();
            }
        }
        if (auth != null) userName = auth.getName();
        return userName;
    }
}
