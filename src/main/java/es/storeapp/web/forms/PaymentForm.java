package es.storeapp.web.forms;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public class PaymentForm {

    private Boolean defaultCreditCard;

    @NotBlank(message = "El número de tarjeta es obligatorio")
    @Pattern(regexp = "\\d{13,19}", message = "El número de tarjeta debe tener entre 13 y 19 dígitos")
    private String creditCard;

    @NotNull(message = "El CVV es obligatorio")
    @Min(value = 100, message = "El CVV debe tener 3 dígitos")
    @Max(value = 9999, message = "El CVV no puede tener más de 4 dígitos")
    private Integer cvv;

    @NotNull(message = "El mes de expiración es obligatorio")
    @Min(value = 1)
    @Max(value = 12)
    private Integer expirationMonth;

    @NotNull(message = "El año de expiración es obligatorio")
    @Min(value = 2024)
    @Max(value = 2100)
    private Integer expirationYear;

    private Boolean save;

    public Boolean getDefaultCreditCard() {
        return defaultCreditCard;
    }

    public void setDefaultCreditCard(Boolean defaultCreditCard) {
        this.defaultCreditCard = defaultCreditCard;
    }
    
    public String getCreditCard() {
        return creditCard;
    }

    public void setCreditCard(String creditCard) {
        this.creditCard = creditCard;
    }

    public Integer getCvv() {
        return cvv;
    }

    public void setCvv(Integer cvv) {
        this.cvv = cvv;
    }

    public Integer getExpirationMonth() {
        return expirationMonth;
    }

    public void setExpirationMonth(Integer expirationMonth) {
        this.expirationMonth = expirationMonth;
    }

    public Integer getExpirationYear() {
        return expirationYear;
    }

    public void setExpirationYear(Integer expirationYear) {
        this.expirationYear = expirationYear;
    }

    public Boolean getSave() {
        return save;
    }

    public void setSave(Boolean save) {
        this.save = save;
    }
    
}
