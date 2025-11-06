package es.storeapp.web.interceptors;

import com.fasterxml.jackson.core.ObjectCodec;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.storeapp.business.entities.User;
import es.storeapp.business.services.UserService;
import es.storeapp.common.Constants;
import es.storeapp.web.cookies.UserInfo;
import java.beans.XMLDecoder;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.web.servlet.HandlerInterceptor;

public class AutoLoginInterceptor implements HandlerInterceptor {

    private final UserService userService;
    private static final ObjectMapper objectMapper = new ObjectMapper();

    public AutoLoginInterceptor(UserService userService) {
        this.userService = userService;
    }

    private static UserInfo base64ToUserInfo(String base64) {
        try {
            byte[] decoded = Base64.getDecoder().decode(base64);
            String json = new String(decoded, StandardCharsets.UTF_8);
            return objectMapper.readValue(json, UserInfo.class);
        } catch (Exception e) {
            throw new RuntimeException("Error deserializing user info", e);
        }
    }

    private void removeInvalidCookie(HttpServletResponse response) {
        Cookie invalidCookie = new Cookie(Constants.PERSISTENT_USER_COOKIE, "");
        invalidCookie.setMaxAge(0);
        invalidCookie.setPath("/");
        response.addCookie(invalidCookie);
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
                if (cookieValue == null) {
                    continue;
                }
                try {
                    // REEMPLAZA el XMLDecoder inseguro por una funcion segura
                    UserInfo userInfo = base64ToUserInfo(cookieValue);

                    User user = userService.findByEmail(userInfo.getEmail());
                    if (user != null && user.getPassword().equals(userInfo.getPassword())) {
                        session.setAttribute(Constants.USER_SESSION, user);
                    } else {
                        // Opcional: eliminar cookie inválida
                        removeInvalidCookie(response);
                    }

                } catch (Exception e) {
                    // Eliminar cookie corrupta o maliciosa
                    removeInvalidCookie(response);
                }
            }
        }
        return true;
    }
}
