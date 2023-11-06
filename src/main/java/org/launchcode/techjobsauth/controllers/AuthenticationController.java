package org.launchcode.techjobsauth.controllers;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import org.launchcode.techjobsauth.models.User;
import org.launchcode.techjobsauth.models.data.UserRepository;
import org.launchcode.techjobsauth.models.dto.LoginFormDTO;
import org.launchcode.techjobsauth.models.dto.RegistrationFormDTO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.Errors;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

import java.util.Optional;

@Controller
public class AuthenticationController {
    @Autowired
    private UserRepository userRepository;
    private static final String userSessionKey = "user";

    private static void setUserInSession(HttpSession session, User user) {
        session.setAttribute(userSessionKey, user.getId());
    }

    public User getUserFromSession(HttpSession session) {
        Integer userId = (Integer) session.getAttribute(userSessionKey);

        if (userId == null) {
            return null;
        }

        Optional<User> userOptional = userRepository.findById(userId);

        if (userOptional.isEmpty()) {
            return null;
        }

        return userOptional.get();
    }


    //Handlers

    @GetMapping("/register")
    public String displayRegistrationForm(Model model) {
        model.addAttribute(new RegistrationFormDTO());
        return "register";
    }

    @PostMapping("/register")
    public String processRegistrationForm(@ModelAttribute @Valid RegistrationFormDTO registrationFormDTO, Errors errors, Model model, HttpServletRequest request) {

        //Send user back if errors are found
        if (errors.hasErrors()) {
            return "register";
        }
        //Look up user in database using username they provided in the form

        User existingUser = userRepository.findByUsername(registrationFormDTO.getUsername());

        //Send user back if username already exists

        if (existingUser != null) {
            errors.rejectValue("username", "username.alreadyExists", "A user with that username already exists.");
            return "register";
        }

        //Send user back if passwords don't match
        String password = registrationFormDTO.getPassword();
        String verifyPassword = registrationFormDTO.getVerifyPassword();
        if (!password.equals(verifyPassword)) {
            errors.rejectValue("verifyPassword", "password.mismatch", "Passwords do not match.");
            return "register";
        }

        //Otherwise, save user object in database, start new session. redirect

        User newUser = new User(registrationFormDTO.getUsername(), registrationFormDTO.getPassword());
        userRepository.save(newUser);
        setUserInSession(request.getSession(), newUser);
        return "redirect:/index";

    }

    @GetMapping("/login")
    public String displayLoginForm(Model model) {
        model.addAttribute(new LoginFormDTO());
        return "login";
    }

    @PostMapping("/login")
    public String processLoginForm(@ModelAttribute @Valid LoginFormDTO loginFormDTO, Errors errors, HttpServletRequest request, Model model) {
        //Send user back to form if there are errors
        if (errors.hasErrors()) {
            return "register";
        }
        //Look yo user in database using username they provided in the form

        User existingUser = userRepository.findByUsername(loginFormDTO.getUsername());

        // Get password the user supplied in form

        String password = loginFormDTO.getPassword();

        //Security through obscurity ^ - don't reveal which one was the problem

        if(existingUser == null || !existingUser.isMatchingPassword(password)) {
            errors.rejectValue("password",
                    "login.invalid",
                    "Invalid field(s). Please try again.");
            return "login";
        }


        //Otherwise, create new session for user and redirect

        setUserInSession(request.getSession(), existingUser);
        return "redirect:/index";


    }

    //Handle logout
    @GetMapping("/logout")
    public String logout(HttpServletRequest request) {
        request.getSession().invalidate();
        return "redirect:/login";

    }
}
