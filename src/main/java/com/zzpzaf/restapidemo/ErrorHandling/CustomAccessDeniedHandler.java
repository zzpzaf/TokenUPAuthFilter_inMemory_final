package com.zzpzaf.restapidemo.ErrorHandling;


import java.io.StringWriter;
import java.text.SimpleDateFormat;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.web.access.AccessDeniedHandler;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class CustomAccessDeniedHandler implements AccessDeniedHandler {

    public void handle(HttpServletRequest request, 
                       HttpServletResponse response,
                       org.springframework.security.access.AccessDeniedException accessDeniedException)
                       throws java.io.IOException, ServletException {
            
        
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        int status = HttpServletResponse.SC_FORBIDDEN;
        String path = request.getRequestURI();
        String msg = "Insufficient Privileges - " + accessDeniedException.getMessage() ;

        response.setStatus(status);
        StringWriter writer = new StringWriter();
        writer.write("{ ");
        writer.write("\"timestamp\": \"" + new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SXXX").format(new java.util.Date())  +  "\",");
        writer.write("\"status\":" + status +  ",");
        writer.write("\"error\": \"" + HttpStatus.valueOf(status).getReasonPhrase() + "\",");
        writer.write("\"massage\": \"" +  msg +  "\",");
        writer.write("\"path\": \"" + path  +  "\"");
        writer.write(" }");
        
        response.getWriter().write(writer.toString());
    }

}

