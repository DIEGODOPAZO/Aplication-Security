package es.storeapp.web.interceptors;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.servlet.HandlerInterceptor;

public class CSPInterceptor implements HandlerInterceptor {

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws Exception {
        response.setHeader("Content-Security-Policy",
                "default-src 'self'; " +                            //solo recursos de mi origen
                        "img-src 'self' data:; " +                              //solo imagenes de mi dominio
                        "script-src 'self' 'unsafe-inline'; " +                 //solo js de mi app
                        "style-src 'self' 'unsafe-inline';"+                    //solo css de mi dominio
                        "object-src 'none';"+                                   //prohibe el uso de flash, java applets, etc
                        "base-uri 'self'; "+                                    //prohibe que cambien la uri
                        "connect-src 'self'; "+                                 //prohibe conexiones AJAX fuera de mi dominio
                        "frame-ancestors 'none';"+                              //prohibe clickjacking xq no deja embeber en iframe
                        "form-action 'self';");                                 //solo envia forms a mi dominio
        return true;
    }

}