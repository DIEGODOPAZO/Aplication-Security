package es.storeapp.business.entities;

import com.fasterxml.jackson.annotation.JsonIgnore;
import es.storeapp.common.Constants;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import jakarta.persistence.AttributeOverride;
import jakarta.persistence.AttributeOverrides;
import jakarta.persistence.Column;
import jakarta.persistence.Embedded;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

@Entity(name = Constants.USER_ENTITY)
@Table(name = Constants.USERS_TABLE)
public class User implements Serializable {

    private static final long serialVersionUID = 570528466125178223L;

    public User() {
    }

    public User(String name, String email, String password, String address, String image) {
        this.name = name;
        this.email = email;
        this.password = password;
        this.address = address;
        this.image = image;
    }

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long userId;

    @NotBlank
    @Size(max = 100)
    @Pattern(regexp = "[\\p{L}0-9 \\-_'.,]+", message = "Nombre contiene caracteres no permitidos")
    @Column(name = "name", nullable = false, unique = false, length = 100)
    private String name;

    @NotBlank
    @Email
    @Size(max = 255)
    @Column(name = "email", nullable = false, unique = true, length = 255)
    private String email;

    @NotBlank
    @Size(min = 8, max = 255) // mínimo 8; límite superior generoso para acomodar hashes largos
    @JsonIgnore
    @Column(name = "password", nullable = false, length = 255)
    private String password;

    @NotBlank
    @Size(max = 500)
    @Column(name = "address", nullable = false, length = 500)
    private String address;

    @JsonIgnore
    @Column(name = "resetPasswordToken")
    private String resetPasswordToken;

    @Embedded
    @AttributeOverrides(value = {
            @AttributeOverride(name = "card", column = @Column(name = "card")),
            @AttributeOverride(name = "cvv", column = @Column(name = "CVV")),
            @AttributeOverride(name = "expirationMonth", column = @Column(name = "expirationMonth")),
            @AttributeOverride(name = "expirationYear", column = @Column(name = "expirationYear"))
    })
    @JsonIgnore
    private CreditCard card;

    @Size(max = 255)
    @Column(name = "image", length = 255)
    private String image;

    @OneToMany(mappedBy = "user")
    private List<Comment> comments = new ArrayList<>();

    public Long getUserId() {
        return userId;
    }

    public void setUserId(Long userId) {
        this.userId = userId;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    @JsonIgnore
    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getAddress() {
        return address;
    }

    public void setAddress(String address) {
        this.address = address;
    }

    public String getImage() {
        return image;
    }

    public void setImage(String image) {
        this.image = image;
    }

    public CreditCard getCard() {
        return card;
    }

    public void setCard(CreditCard card) {
        this.card = card;
    }

    public List<Comment> getComments() {
        return comments;
    }

    public void setComments(List<Comment> comments) {
        this.comments = comments;
    }

    @JsonIgnore
    public String getResetPasswordToken() {
        return resetPasswordToken;
    }

    public void setResetPasswordToken(String resetPasswordToken) {
        this.resetPasswordToken = resetPasswordToken;
    }

    @Override
    public String toString() {
        return String.format("User{userId=%s, name=%s, email=%s, password=%s, address=%s, resetPasswordToken=%s, card=%s, image=%s}",
                userId, name, email, password, address, resetPasswordToken, card, image);
    }

}
