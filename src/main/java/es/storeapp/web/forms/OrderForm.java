package es.storeapp.web.forms;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public class OrderForm {

    @NotBlank(message = "El nombre es obligatorio")
    @Size(max = 100, message = "El nombre no puede superar los 100 caracteres")
    private String name;

    @Min(value = 0, message = "El precio no puede ser negativo")
    private int price;

    @NotBlank(message = "La dirección es obligatoria")
    @Size(max = 500, message = "La dirección no puede superar los 500 caracteres")
    private String address;

    @NotNull
    private Boolean payNow;
    
    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public int getPrice() {
        return price;
    }

    public void setPrice(int price) {
        this.price = price;
    }

    public String getAddress() {
        return address;
    }

    public void setAddress(String address) {
        this.address = address;
    }

    public Boolean getPayNow() {
        return payNow;
    }

    public void setPayNow(Boolean payNow) {
        this.payNow = payNow;
    }
        
}
