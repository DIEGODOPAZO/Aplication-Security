package es.storeapp.web.forms;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public class CommentForm {

    @NotNull(message = "El producto es obligatorio")
    private Long productId;

    @NotNull(message = "El comentario no puede estar vacío")
    @Size(min = 3, max = 500, message = "El comentario debe tener entre 3 y 500 caracteres")
    private String text;

    @NotNull(message = "La valoración es obligatoria")
    @Min(value = 1, message = "La valoración mínima es 1")
    @Max(value = 5, message = "La valoración máxima es 5")
    private Integer rating;

    public String getText() {
        return text;
    }

    public void setText(String text) {
        this.text = text;
    }

    public Integer getRating() {
        return rating;
    }

    public void setRating(Integer rating) {
        this.rating = rating;
    }

    public Long getProductId() {
        return productId;
    }

    public void setProductId(Long productId) {
        this.productId = productId;
    }

    
}
