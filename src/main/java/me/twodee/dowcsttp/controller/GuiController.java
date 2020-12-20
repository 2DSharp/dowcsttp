package me.twodee.dowcsttp.controller;

import lombok.Data;
import lombok.Getter;
import lombok.Setter;
import me.twodee.dowcsttp.Helper;
import me.twodee.dowcsttp.ResultObject;
import me.twodee.dowcsttp.model.dto.User;
import me.twodee.dowcsttp.service.Accounts;
import me.twodee.dowcsttp.service.Transactions;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpSession;
import javax.validation.Valid;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Controller
public class GuiController {

    private final Accounts accounts;
    private final Transactions transactions;

    public GuiController(Accounts accounts, Transactions transactions) {
        this.accounts = accounts;
        this.transactions = transactions;
    }

    @GetMapping("/register")
    public String register(Model formModel) {
        formModel.addAttribute("title", "Create a new account");
        return "register";
    }

    @PostMapping("/register")
    public String register(@Valid User.RegistrationData data, BindingResult result, Model formModel) {

        if (result.hasErrors()) {
            formModel.addAttribute("error", result.getFieldErrors().get(0).getDefaultMessage());
        } else {
            ResultObject registrationResult = accounts.register(data);
            if (registrationResult.isSuccessful) {
                formModel.addAttribute("complete", true);
            } else {
                System.out.println(registrationResult.error);
                formModel.addAttribute("error", registrationResult.error);
            }
        }
        Map<String, String> values = new HashMap<>();
        Helper.addNotNull(values, "name", data.name);
        Helper.addNotNull(values, "email", data.email);

        formModel.addAttribute("values", values);
        return register(formModel);
    }

    @GetMapping("/")
    public String loginView(Model model, HttpSession session) {
        model.addAttribute("title", "Login - MockTTP");
        session.setAttribute("csrf_token", UUID.randomUUID().toString());
        model.addAttribute("csrf_token", session.getAttribute("csrf_token"));
        return "login";
    }

    @GetMapping("/dashboard")
    public String dashboard(Model model, HttpSession session) {

        if (session.getAttribute("loggedIn") != null) {
            model.addAttribute("title", "Dashboard - MockTTP");
            return "dashboard";
        }
        return "redirect:/";
    }

    @PostMapping("/")
    public String login(@Valid User.LoginData data, BindingResult result, HttpSession session, Model model) {
        try {
            Map<String, String> values = new HashMap<>();
            Helper.addNotNull(values, "name", data.identifier);
            model.addAttribute("values", values);

            if (result.hasErrors()) {
                model.addAttribute("error", result.getFieldErrors().get(0).getDefaultMessage());
                return loginView(model, session);
            }

            if (!session.getAttribute("csrf_token").equals(data.csrf)) {
                model.addAttribute("error", "Invalid login request");
                return loginView(model, session);
            }

            if (!accounts.hasCorrectCredentials(data)) {
                model.addAttribute("error", "The credentials you supplied are invalid");
                return loginView(model, session);
            }

            accounts.login(data.identifier);
            return "redirect:/dashboard";

        } catch (Throwable e) {
            model.addAttribute("error", "Something went wrong");
        }
        return loginView(model, session);
    }

    @GetMapping("/register/pws")
    public String registerPwsView(Model model) {
        model.addAttribute("title", "Register PWS - MockTTP");
        return "pws_registration";
    }
    @Data
    public static class LoginIdentity {
        public String identifier;
        public String password;
    }

    public static class AuthorizationDto {
        public LoginIdentity loginIdentity;
        public String initiationToken;
    }

    @Getter
    @Setter
    public static class LoginLoginIdentityWithMFA extends LoginIdentity {
        public String mfaData;
    }


//
//    @PostMapping("/login")
//    public <T> ResponseEntity<T> login(LoginIdentity loginIdentity) {
//
//        if (accounts.hasCorrectCredentials(loginIdentity)) {
//            accounts.login(loginIdentity);
//            // handle success
//        }
//        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
//    }
//
//    @PostMapping("/authorize")
//    public Object login(AuthorizationDto authorizationDto, HttpSession session) {
//
//        if (accounts.hasCorrectCredentials(authorizationDto.loginIdentity) && session.getAttribute("initiationToken").equals(authorizationDto.initiationToken)) {
//            accounts.login(authorizationDto.loginIdentity);
//            // get the transaction identity related to the user identity and pws identity
//            String transactionIdentity = transactionManager.getTransactionIdentity(session, authorizationDto.loginIdentity.identifier);
//            String authToken = transactionManager.getAuthToken(authorizationDto.loginIdentity.identifier);
//            accounts.getPws(transactionIdentity).getRedirectUrl();
//
//        }
//        return new ResponseEntity<String>("https://facebook.com", HttpStatus.MOVED_PERMANENTLY);
//
//    }
//
//    @GetMapping("/authorize")
//    public ResponseEntity showAuthorizationPage(@RequestParam("pws_identifier") String pwsIdentifier, HttpSession session) {
//        String initiationToken = transactionManager.generateInitiationToken(session, pwsIdentifier);
//        // pass the token to moustache
//    }
}
