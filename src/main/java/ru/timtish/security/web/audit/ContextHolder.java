package ru.timtish.security.web.audit;

import javax.servlet.http.HttpServletRequest;

public interface ContextHolder {
    String getAuthUserName(HttpServletRequest req);
}
