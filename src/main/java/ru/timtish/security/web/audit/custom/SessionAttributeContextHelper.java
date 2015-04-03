package ru.timtish.security.web.audit.custom;

import ru.timtish.security.web.audit.ContextHolder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

/**
 * Получение залогиненого пользователя из атрибута сессии.
 */
public class SessionAttributeContextHelper implements ContextHolder {

    private String userNameAttribute;

    public SessionAttributeContextHelper(String userNameAttribute) {
        this.userNameAttribute = userNameAttribute;
    }

    public String getAuthUserName(HttpServletRequest req) {
        HttpSession session = req.getSession(false);
        return session == null ? null : String.valueOf(session.getAttribute(userNameAttribute));
    }

    public void setAuthUserName(HttpServletRequest req, String userName) {
        if (userName != null) {
            HttpSession session = req.getSession(true);
            session.setAttribute(userNameAttribute ,userName);
        } else {
            HttpSession session = req.getSession(false);
            if (session != null) {
                session.removeAttribute(userNameAttribute);
            }
        }
    }
}
