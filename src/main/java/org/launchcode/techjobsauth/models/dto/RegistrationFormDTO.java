package org.launchcode.techjobsauth.models.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public class RegistrationFormDTO extends LoginFormDTO {

    @NotNull(message = "Field required")
    @NotBlank(message = "Field required")
    @Size(min = 8, max = 30, message = "Password must be 8-30 characters long")
    private String verifyPassword;

    public String getVerifyPassword() {
        return verifyPassword;
    }

    public void setVerifyPassword(String verifyPassword) {
        this.verifyPassword = verifyPassword;
    }

}
