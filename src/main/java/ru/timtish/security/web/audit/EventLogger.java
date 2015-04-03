package ru.timtish.security.web.audit;

import org.apache.log4j.Logger;

import java.util.StringTokenizer;

/**
 * @author timtish@gmail.com
 */
public class EventLogger {

    private static final Logger LOG = Logger.getLogger(AuditContextService.class);

    public void log(SecurityContext ctx, AuditEvent event) {
        String eventString = eventToString(ctx, event);
        if (eventString != null) {
            LOG.info(eventString);
        }
    }

    protected String eventToString(SecurityContext ctx, AuditEvent event) {
        String userName = "null";
        String ip = "null";

        if (ctx != null) {
            userName = ctx.getUserName();
            ip = ctx.getIp();
        }

        StringBuffer sb = new StringBuffer();
        sb.append(userName);
        sb.append("|");
        sb.append(ip);
        sb.append("|");
        sb.append(event.getAction() == null ? "null" : stripNewLines(event.getAction()));
        sb.append("|");
        sb.append(event.getMessage() == null ? "null" : stripNewLines(event.getMessage()));
        return sb.toString();
    }

    protected static String stripNewLines(String inputString) {
        if ((inputString == null) || (inputString.trim().equals(""))) {
            return inputString;
        }
        StringBuffer sb = new StringBuffer(inputString.length());

        for (StringTokenizer st = new StringTokenizer(inputString, "\r\n"); st.hasMoreTokens(); ) {
            if (sb.length() > 0) {
                sb.append(" ");
            }
            sb.append(st.nextToken());
        }
        return sb.toString();
    }

}
