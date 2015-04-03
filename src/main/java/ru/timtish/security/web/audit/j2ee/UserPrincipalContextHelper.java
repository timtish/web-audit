package ru.timtish.security.web.audit.j2ee;

import ru.timtish.security.web.audit.ContextHolder;

import javax.servlet.http.HttpServletRequest;
import java.security.Principal;

/**
 * Получение имени пользователя из HttpServletRequest#getUserPrincipal().
 */
public class UserPrincipalContextHelper implements ContextHolder {

    public String getAuthUserName(HttpServletRequest req) {
        Principal principal = req.getUserPrincipal();
        return principal == null ? null : principal.getName();
    }

}
