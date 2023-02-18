package com.zzpzaf.restapidemo.Configuration;

import java.io.IOException;
import org.springframework.util.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationEntryPointFailureHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import com.zzpzaf.restapidemo.ErrorHandling.CustomAuthenticationEntryPoint;
import com.zzpzaf.restapidemo.Utils.TokenUtils;

 // Version 4 - Performs both: Basic Authentication and JWT Bearer token Authorization 
 // with custom authorization and authentication error handling
 public class CustomRequestHeaderTokenFilter extends UsernamePasswordAuthenticationFilter{

    private final Log logger = LogFactory.getLog(getClass());
    private AuthenticationManager authManager;
    private UserDetailsService userService;
    private CustomAuthenticationEntryPoint authPoint;

    private String uri;

    public CustomRequestHeaderTokenFilter(AuthenticationManager authManager) {
        super(authManager);
        this.authManager = authManager;
    }

    @Autowired
    public void setUserDetailsService(UserDetailsService userService) {
        this.userService = userService;
    } 

    @Autowired
    public void setAuthPoint(CustomAuthenticationEntryPoint authPoint) {
        this.authPoint = authPoint;
        setAuthenticationFailureHandler(new AuthenticationEntryPointFailureHandler(authPoint));
    } 


    @Override
    public void doFilter(jakarta.servlet.ServletRequest request,
                         jakarta.servlet.ServletResponse response, 
                         jakarta.servlet.FilterChain chain) throws IOException, ServletException {
        //logger.info("==>>  Attempting Authorization ... ");

        HttpServletRequest req = (HttpServletRequest) request;
        uri = req.getRequestURI();
        logger.info("==>>  Attempting Authorization for " + uri + " ... ");
        String uname = getUsernameFromBearerToken(req.getHeader(SecurityConstants.AUTH_HEADER));
        //User is an org.springframework.security.core.userdetails.User object
        User user = (User) userService.loadUserByUsername(uname);
        if (user != null) {
            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(uname, null, user.getAuthorities());
            SecurityContext context = SecurityContextHolder.createEmptyContext();
            context.setAuthentication(authentication);
            SecurityContextHolder.setContext(context);
            
            logger.info("===>>> (Authorized) Authentication: " + authentication.toString());

        }

        super.doFilter(request, response, chain); 

    }



    @Override
    public Authentication attemptAuthentication(jakarta.servlet.http.HttpServletRequest request,
                                                jakarta.servlet.http.HttpServletResponse response)
                                                throws AuthenticationException {

         logger.info("==>>  Attempting Authentication ... ");
         UsernamePasswordAuthenticationToken unAuthenticatedToken = getUnauthenticatedToken(request.getHeader(SecurityConstants.AUTH_HEADER));
         logger.info(" ==>> UnauthenticatedToken: " + unAuthenticatedToken.toString());
         Authentication authResult = this.authManager.authenticate(unAuthenticatedToken);
         logger.info("(Authenticated) Authentication: " + authResult.toString());
            
         return authResult;
    }



    @Override
    protected void successfulAuthentication(jakarta.servlet.http.HttpServletRequest request,
                                            jakarta.servlet.http.HttpServletResponse response,
                                            jakarta.servlet.FilterChain chain,
                                            Authentication authResult)
                                            throws IOException, jakarta.servlet.ServletException {
    
        logger.info("==>> SUCCESSFUL Authentication!  " + authResult.toString());

        String uname = (String) authResult.getPrincipal();
        String token = TokenUtils.generateJWTUserToken(uname);  
        logger.info("Generated JWT Token: " + token);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        response.addHeader(SecurityConstants.AUTH_HEADER, SecurityConstants.BEARER_TOKEN_PREFIX + token);
        response.getWriter().write("{ \"Success!\": \" You are now authenticated! - Find your authorization token in this response '"+ (SecurityConstants.AUTH_HEADER) + "'' header.\" }");

    }


    // @Override
    // protected void  unsuccessfulAuthentication(jakarta.servlet.http.HttpServletRequest request, 
    //                                            jakarta.servlet.http.HttpServletResponse response, 
    //                                            AuthenticationException failed) 
    //                                            throws IOException, jakarta.servlet.ServletException {
    //     logger.info("==>> UN-SUCCESSFUL Authentication! " + failed.getMessage());

    //     If we have used this method, we could have, for instance, sent an error response similar to the one below:

    //     response.setHeader("WWW-Authenticate", "Basic realm=\"Access to /signin authentication endpoint\"");
    //     response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    //     response.getWriter().write("{ \"Error\": \"" + failed.getMessage()  +  ".\" }");

    // }


    private UsernamePasswordAuthenticationToken getUnauthenticatedToken(String headerToken) {

        UsernamePasswordAuthenticationToken unAuthenticatedToken = new UsernamePasswordAuthenticationToken("", "");
        
        if (!isAuthorizationHeader(headerToken, SecurityConstants.BASIC_TOKEN_PREFIX) ) {
            String msg = "Authorization Header for Basic Authentication not provided or is null or invalid";
            logger.info("==>>" + msg + "! ");
            updateAuthenticatonError(msg);
            return unAuthenticatedToken;
        }     
        headerToken = StringUtils.delete(headerToken, SecurityConstants.BASIC_TOKEN_PREFIX).trim();
        try {
            String[] uNamePasswordPair = TokenUtils.decodedBase64(headerToken);
            unAuthenticatedToken =  new UsernamePasswordAuthenticationToken(uNamePasswordPair[0], uNamePasswordPair[1]);
        } catch (Exception ex) {
            String msg = "Error getting the Authorization Header"+ ex.getMessage();
            logger.info("==>>" + msg + "! ");
            updateAuthenticatonError(msg);
        }
        return unAuthenticatedToken;
    }

    private boolean isAuthorizationHeader(String headerToken, String prefix) {

        if (headerToken == null || headerToken.trim().isEmpty() || !headerToken.startsWith(prefix) ) {
            return false;
        } 
        return true;

    }
    
    // Inside this method we want to make clear that any error occurs concerns authorization and not authentication
    // So, whereas is necessary we call the updateAuthorizationError() to update our CustomAuthenticationEntryPoint class 
    private String getUsernameFromBearerToken(String headerToken) {
        String uname = "";
        String msg = "" ;

        if (!isAuthorizationHeader(headerToken, SecurityConstants.BEARER_TOKEN_PREFIX) ) {
            msg = "Authorization Header for Bearer (JWT) Authorization not provided or is null or invalid!";
            updateAuthorizationError(msg);
            logger.info("==>> " + msg);
            return "";
        } 
        headerToken = StringUtils.delete(headerToken, SecurityConstants.BEARER_TOKEN_PREFIX).trim();
        try {
            uname = TokenUtils.getUsernameFromJWTUserToken(headerToken);
            if (uname != null) return uname; 
        } catch (Exception ex) {
            msg = "Error getting the Username from Bearer JWT token! - " + ex.getMessage();
            updateAuthorizationError(msg);
            logger.info("==>> " + msg);
        }

        return uname;
    }


    // This is the method that updates the properties in our CustomAuthenticationEntryPoint class
    private void updateAuthorizationError(String msg) {

        if (uri.endsWith(SecurityConstants.SIGN_IN_URI_ENDING)) {
            // If, for any reason, the request uri concerns the Basic Authentication endpoint reset 
            // the properties to their initial values (Authentication related).
            this.authPoint.setInitValues();
            this.authPoint.setPath(this.uri);
            return;
        }

        // Set the properties for Authoriazation error responses    
        this.authPoint.setPath(this.uri);
        this.authPoint.setStatus(HttpServletResponse.SC_FORBIDDEN);
        this.authPoint.setRealmAuthSchema(SecurityConstants.BEARER_TOKEN_PREFIX);
        
        this.authPoint.setCustomMessage(msg);
    
    } 

    //This is just added for handling errors specific to our filter inner authentication failures.
    private void updateAuthenticatonError(String msg) {
        //this.authPoint.setInitValues();
        this.authPoint.setPath(this.uri);
        this.authPoint.setCustomMessage(msg);
    }


}

