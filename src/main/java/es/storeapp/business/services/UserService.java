package es.storeapp.business.services;

import es.storeapp.business.entities.User;
import es.storeapp.business.exceptions.AuthenticationException;
import es.storeapp.business.exceptions.DuplicatedResourceException;
import es.storeapp.business.exceptions.InstanceNotFoundException;
import es.storeapp.business.exceptions.ServiceException;
import es.storeapp.business.repositories.UserRepository;
import es.storeapp.business.utils.ExceptionGenerationUtils;
import es.storeapp.common.ConfigurationParameters;
import es.storeapp.common.Constants;

import java.io.*;
import java.nio.file.Files;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import jakarta.annotation.PostConstruct;
import org.apache.commons.compress.utils.IOUtils;
import org.apache.commons.mail.HtmlEmail;
import org.mindrot.jbcrypt.BCrypt;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ar.com.hjg.pngj.ImageInfo;
import ar.com.hjg.pngj.PngReader;

@Service
public class UserService {

    private static final Logger logger = LoggerFactory.getLogger(UserService.class);

    // Eliminar salt
    // private static final String SALT = "$2a$10$MN0gK0ldpCgN9jx6r0VYQO";

    @Autowired
    ConfigurationParameters configurationParameters;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private MessageSource messageSource;

    @Autowired
    ExceptionGenerationUtils exceptionGenerationUtils;

    private File resourcesDir;

    @PostConstruct
    public void init() {
        resourcesDir = new File(configurationParameters.getResources());
    }

    @Transactional(readOnly = true)
    public User findByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    @Transactional(readOnly = true)
    public User login(String email, String clearPassword) throws AuthenticationException {
        User user = userRepository.findByEmail(email);
        if (user == null) {
            throw exceptionGenerationUtils.toAuthenticationException(Constants.AUTH_INVALID_USER_MESSAGE, email);
        }

        // ✅ Usar BCrypt.checkpw() para comparar contraseñas
        if (!BCrypt.checkpw(clearPassword, user.getPassword())) {
            throw exceptionGenerationUtils.toAuthenticationException(Constants.AUTH_INVALID_PASSWORD_MESSAGE, email);
        }

        return user;
    }

    @Transactional()
    public void sendResetPasswordEmail(String email, String url, Locale locale)
            throws AuthenticationException, ServiceException {
        User user = userRepository.findByEmail(email);
        if (user == null) {
            throw exceptionGenerationUtils.toAuthenticationException(Constants.AUTH_INVALID_USER_MESSAGE, email);
        }
        String token = UUID.randomUUID().toString();

        try {

            System.setProperty("mail.smtp.ssl.protocols", "TLSv1.2");

            HtmlEmail htmlEmail = new HtmlEmail();
            htmlEmail.setHostName(configurationParameters.getMailHost());
            htmlEmail.setSmtpPort(configurationParameters.getMailPort());
            htmlEmail.setSslSmtpPort(Integer.toString(configurationParameters.getMailPort()));
            htmlEmail.setAuthentication(configurationParameters.getMailUserName(),
                    configurationParameters.getMailPassword());
            htmlEmail.setSSLOnConnect(configurationParameters.getMailSslEnable() != null
                    && configurationParameters.getMailSslEnable());
            if (configurationParameters.getMailStartTlsEnable()) {
                htmlEmail.setStartTLSEnabled(true);
                htmlEmail.setStartTLSRequired(true);
            }
            htmlEmail.addTo(email, user.getName());
            htmlEmail.setFrom(configurationParameters.getMailFrom());
            htmlEmail.setSubject(messageSource.getMessage(Constants.MAIL_SUBJECT_MESSAGE,
                    new Object[]{user.getName()}, locale));

            String link = url + Constants.PARAMS
                    + Constants.TOKEN_PARAM + Constants.PARAM_VALUE + token + Constants.NEW_PARAM_VALUE
                    + Constants.EMAIL_PARAM + Constants.PARAM_VALUE + email;

            htmlEmail.setHtmlMsg(messageSource.getMessage(Constants.MAIL_TEMPLATE_MESSAGE,
                    new Object[]{user.getName(), link}, locale));

            htmlEmail.setTextMsg(messageSource.getMessage(Constants.MAIL_HTML_NOT_SUPPORTED_MESSAGE,
                    new Object[0], locale));

            htmlEmail.send();
        } catch (Exception ex) {
            logger.error(ex.getMessage(), ex);
            throw new ServiceException(ex.getMessage());
        }

        user.setResetPasswordToken(token);
        userRepository.update(user);
    }

    @Transactional
    public User create(String name, String email, String password, String address,
            String image, byte[] imageContents) throws DuplicatedResourceException {
        if (userRepository.findByEmail(email) != null) {
            throw exceptionGenerationUtils.toDuplicatedResourceException(Constants.EMAIL_FIELD, email,
                    Constants.DUPLICATED_INSTANCE_MESSAGE);
        }
        // Generar un salt dinámico para cada usuario
        String hashedPassword = BCrypt.hashpw(password, BCrypt.gensalt());

        User user = userRepository.create(new User(name, email, hashedPassword, address, image));
        saveProfileImage(user.getUserId(), image, imageContents);
        return user;
    }

    @Transactional
    public User update(Long id, String name, String email, String address, String image, byte[] imageContents)
            throws DuplicatedResourceException, InstanceNotFoundException, ServiceException {
        User user = userRepository.findById(id);
        User emailUser = userRepository.findByEmail(email);
        if (emailUser != null && !Objects.equals(emailUser.getUserId(), user.getUserId())) {
            throw exceptionGenerationUtils.toDuplicatedResourceException(Constants.EMAIL_FIELD, email,
                    Constants.DUPLICATED_INSTANCE_MESSAGE);
        }
        user.setName(name);
        user.setEmail(email);
        user.setAddress(address);
        if (image != null && image.trim().length() > 0 && imageContents != null) {
            try {
                deleteProfileImage(id, user.getImage());
            } catch (Exception ex) {
                logger.error(ex.getMessage(), ex);
            }
            saveProfileImage(id, image, imageContents);
            user.setImage(image);
        }
        return userRepository.update(user);
    }

    @Transactional
    public User changePassword(Long id, String oldPassword, String password)
            throws InstanceNotFoundException, AuthenticationException {
        User user = userRepository.findById(id);
        if (user == null) {
            throw exceptionGenerationUtils.toAuthenticationException(
                    Constants.AUTH_INVALID_USER_MESSAGE, id.toString());
        }
        // Verificar contraseña anterior
        if (!BCrypt.checkpw(oldPassword, user.getPassword())) {
            throw exceptionGenerationUtils.toAuthenticationException(Constants.AUTH_INVALID_PASSWORD_MESSAGE, id.toString());
        }

        // Guardar la nueva con nuevo salt
        user.setPassword(BCrypt.hashpw(password, BCrypt.gensalt()));
        return userRepository.update(user);
    }

    @Transactional
    public User changePassword(String email, String password, String token) throws AuthenticationException {
        User user = userRepository.findByEmail(email);
        if (user == null) {
            throw exceptionGenerationUtils.toAuthenticationException(Constants.AUTH_INVALID_USER_MESSAGE, email);
        }
        if (user.getResetPasswordToken() == null || !user.getResetPasswordToken().equals(token)) {
            throw exceptionGenerationUtils.toAuthenticationException(Constants.AUTH_INVALID_TOKEN_MESSAGE, email);
        }
        user.setPassword(BCrypt.hashpw(password, BCrypt.gensalt()));
        user.setResetPasswordToken(null);
        return userRepository.update(user);
    }

    @Transactional
    public User removeImage(Long id) throws InstanceNotFoundException, ServiceException {
        User user = userRepository.findById(id);
        try {
            deleteProfileImage(id, user.getImage());
        } catch (IOException ex) {
            logger.error(ex.getMessage(), ex);
            throw new ServiceException(ex.getMessage());
        }
        user.setImage(null);
        return userRepository.update(user);
    }

    @Transactional
    public byte[] getImage(Long id) throws InstanceNotFoundException {
        User user = userRepository.findById(id);
        try {
            return getProfileImage(id, user.getImage());
        } catch (IOException ex) {
            logger.error(ex.getMessage(), ex);
            return null;
        }
    }

    private static boolean isValidPng(InputStream inputStream) {
        PngReader png = null;
        try {
            png = new PngReader(inputStream); // usar InputStream en lugar de File
            ImageInfo info = png.imgInfo;
            System.out.println("Ancho: " + info.cols + ", Alto: " + info.rows + ", Bit depth: " + info.bitDepth);
            return true;
        } catch (RuntimeException e) {
            System.out.println("No es un PNG válido: " + e.getMessage());
            return false;
        } finally {
            if (png != null) png.end();
        }
    }
    private static final Set<String> ALLOWED_EXTENSIONS = Set.of("png");
    private static String getFileExtension(String fileName) {
        int lastDot = fileName.lastIndexOf('.');
        if (lastDot == -1) return "";
        return fileName.substring(lastDot + 1);
    }
    private void saveProfileImage(Long id, String image, byte[] imageContents) {
        if (image == null || image.trim().isEmpty() || imageContents == null) return;

        // Verificar extensión
        String extension = getFileExtension(image);
        if (!ALLOWED_EXTENSIONS.contains(extension.toLowerCase())) {
            throw new IllegalArgumentException("Solo se permiten archivos PNG.");
        }

        // Validar PNG en memoria usando ByteArrayInputStream
        try (ByteArrayInputStream bais = new ByteArrayInputStream(imageContents)) {
            if (!isValidPng(bais)) {
                throw new IllegalArgumentException("El archivo subido no es un PNG válido.");
            }
        } catch (Exception e) {
            throw new IllegalArgumentException("Error validando el PNG.", e);
        }

        // Guardar archivo seguro
        File userDir = new File(resourcesDir, id.toString());
        userDir.mkdirs();
        File profilePicture = new File(userDir, image);
        try (FileOutputStream outputStream = new FileOutputStream(profilePicture)) {
            IOUtils.copy(new ByteArrayInputStream(imageContents), outputStream);
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
        }
    }

    private void deleteProfileImage(Long id, String image) throws IOException {
        if (image != null && image.trim().length() > 0) {
            File userDir = new File(resourcesDir, id.toString());
            File profilePicture = new File(userDir, image);
            Files.delete(profilePicture.toPath());
        }
    }

    private byte[] getProfileImage(Long id, String image) throws IOException {
        if (image != null && image.trim().length() > 0) {
            File userDir = new File(resourcesDir, id.toString());
            File profilePicture = new File(userDir, image);
            try (FileInputStream input = new FileInputStream(profilePicture)) {
                return IOUtils.toByteArray(input);
            }
        }
        return null;
    }

}
