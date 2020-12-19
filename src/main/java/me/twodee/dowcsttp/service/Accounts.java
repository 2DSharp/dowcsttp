package me.twodee.dowcsttp.service;

import me.twodee.dowcsttp.Helper;
import me.twodee.dowcsttp.ResultObject;
import me.twodee.dowcsttp.model.dto.User;
import me.twodee.dowcsttp.model.entity.UserIdentity;
import me.twodee.dowcsttp.repository.UserIdentityRepository;
import org.springframework.dao.DataAccessException;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import javax.validation.Validator;
import javax.validation.ValidatorFactory;

@Service
public class Accounts {

    private final UserIdentityRepository repository;

    public Accounts(UserIdentityRepository repository) {
        this.repository = repository;
    }

////    public boolean hasCorrectCredentials(Authorization.LoginIdentity loginIdentity) {
////
////        var storedIdentity = repository.findById(loginIdentity.identifier);
////        return (storedIdentity.isPresent() && passwordIsCorrect(loginIdentity.password, storedIdentity.get().password));
////    }

    private boolean passwordIsCorrect(String plaintext, String hashed) {
        return BCrypt.checkpw(plaintext, hashed);
    }

    public ResultObject register(User.RegistrationData data) {
        try {
            if (repository.existsUserIdentityByEmail(data.email)) {
                return ResultObject.builder().isSuccessful(false).error("The email you provided is already in use").build();
            }
            BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
            String hashedPassword = encoder.encode(data.password);
            repository.save(UserIdentity.builder()
                    .id(Helper.generateUniqueId())
                    .name(data.name)
                    .hashedPassword(hashedPassword)
                    .email(data.email).build());

            return ResultObject.builder().isSuccessful(true).build();
        } catch (DataAccessException e) {
            return ResultObject.builder().isSuccessful(false).error("Something went wrong, try again").build();
        }
    }
}
