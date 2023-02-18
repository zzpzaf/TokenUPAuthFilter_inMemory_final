package com.zzpzaf.restapidemo.ErrorHandling;

import java.io.IOException;
import java.io.StringWriter;
import java.text.SimpleDateFormat;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import com.zzpzaf.restapidemo.Configuration.SecurityConstants;


@Component
public class  CustomAuthenticationEntryPoint implements AuthenticationEntryPoint{
  
    private String path; 
    private int status;  

    private String realmAuthSchema; 
    private String customMessage;  
    private String errorMessage;

    CustomAuthenticationEntryPoint(){
        setInitValues();
    }

    public void setInitValues() {
        this.path = SecurityConstants.SIGN_IN_URI_ENDING; 
        this.realmAuthSchema = SecurityConstants.BASIC_TOKEN_PREFIX.trim();
        this.status = HttpServletResponse.SC_UNAUTHORIZED; 
        this. customMessage = "";
    }


    @Override
    public void commence(HttpServletRequest request, 
                         HttpServletResponse response,
                         AuthenticationException authException) throws IOException, ServletException {


        if (customMessage.isEmpty()) {
            errorMessage = authException.getMessage();
        } else {
            errorMessage = this.customMessage + " - " +  authException.getMessage();
        }    
        response.addHeader(SecurityConstants.REALM_HEADER, this.realmAuthSchema + " realm=\"" + this.path + "\"");
        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        
        response.getWriter().write(getReturnedJsonString() );
        
    }


	public void setPath(String path) {
		this.path = path;
	}

    public void setRealmAuthSchema(String realmAuthSchema) {
        this.realmAuthSchema = realmAuthSchema;
    }


    public void setStatus(int status) {
        this.status = status;
    }


    public void setCustomMessage(String customMessage) {
        this.customMessage = customMessage;
    }

    private String getReturnedJsonString() {

        StringWriter writer = new StringWriter();
        writer.write("{ ");
        writer.write("\"timestamp\": \"" + new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SXXX").format(new java.util.Date())  +  "\",");
        writer.write("\"status\":" + status +  ",");
        writer.write("\"error\": \"" + HttpStatus.valueOf(status).getReasonPhrase() + "\",");
        writer.write("\"massage\": \"" + errorMessage  +  "\",");
        writer.write("\"path\": \"" + path  +  "\"");
        writer.write(" }");

        return writer.toString();
    }


}
