package es.storeapp.web.interceptors;

import es.storeapp.business.entities.User;
import es.storeapp.business.services.UserService;
import es.storeapp.common.Constants;
import es.storeapp.web.cookies.UserInfo;

import java.beans.XMLDecoder;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.web.servlet.HandlerInterceptor;

public class AutoLoginInterceptor implements HandlerInterceptor {

    private final UserService userService;

    // Lista blanca de clases permitidas para deserializar
    private static final Set<String> WHITELISTED_CLASSES = Set.of(
            "es.storeapp.web.cookies.UserInfo"
    );

    public AutoLoginInterceptor(UserService userService) {
        this.userService = userService;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws Exception {

        HttpSession session = request.getSession(true);
        if (session.getAttribute(Constants.USER_SESSION) != null || request.getCookies() == null) {
            return true;
        }

        for (Cookie c : request.getCookies()) {
            if (Constants.PERSISTENT_USER_COOKIE.equals(c.getName())) {
                String cookieValue = c.getValue();
                if (cookieValue == null) continue;

                try {
                    // Decodificar la cookie
                    String xml = new String(Base64.getDecoder().decode(cookieValue), StandardCharsets.UTF_8);

                    // Validar clase antes de deserializar
                    String className = extractClassNameFromXML(xml);
                    if (!WHITELISTED_CLASSES.contains(className)) {
                        throw new SecurityException("Clase no permitida en deserialización: " + className);
                    }

                    // ✅ Deserialización segura (solo si la clase está en la whitelist)
                    try (XMLDecoder xmlDecoder = new XMLDecoder(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)))) {
                        Object obj = xmlDecoder.readObject();

                        if (obj instanceof UserInfo userInfo) {
                            User user = userService.findByEmail(userInfo.getEmail());
                            if (user != null && user.getPassword().equals(userInfo.getPassword())) {
                                session.setAttribute(Constants.USER_SESSION, user);
                            }
                        }
                    }
                } catch (Exception ex) {
                    // Registrar el intento de cookie maliciosa
                    System.err.println("Error al procesar cookie persistente: " + ex.getMessage());
                }
            }
        }

        return true;
    }

    // Extrae el nombre de la clase del XML de forma segura con regex
    private String extractClassNameFromXML(String xml) {
        Pattern pattern = Pattern.compile("<object\\s+class=\"([^\"]+)\"");
        Matcher matcher = pattern.matcher(xml);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return null;
    }
}
