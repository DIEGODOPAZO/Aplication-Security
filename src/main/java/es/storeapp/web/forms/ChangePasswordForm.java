package es.storeapp.web.forms;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public class ChangePasswordForm {

    @NotBlank(message = "La contraseña actual es obligatoria")
    @Size(min = 8, max = 255, message = "La contraseña actual debe tener al menos 8 caracteres")
    private String oldPassword;

    @NotBlank(message = "La nueva contraseña es obligatoria")
    @Size(min = 8, max = 255, message = "La nueva contraseña debe tener al menos 8 caracteres")
    private String password;

    public String getOldPassword() {
        return oldPassword;
    }

    public void setOldPassword(String oldPassword) {
        this.oldPassword = oldPassword;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
