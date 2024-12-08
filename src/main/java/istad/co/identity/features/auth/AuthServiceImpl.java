package istad.co.identity.features.auth;

import istad.co.identity.domain.Passcode;
import istad.co.identity.domain.User;
import istad.co.identity.features.auth.dto.ChangeForgotPasswordRequest;

import istad.co.identity.features.auth.dto.ForgotPasswordRequest;
import istad.co.identity.features.auth.dto.LoginRequest;
import istad.co.identity.features.auth.dto.RegisterRequest;
import istad.co.identity.features.emailverification.EmailVerificationTokenService;
import istad.co.identity.features.password.PasscodeRepository;
import istad.co.identity.features.password.PasscodeService;
import istad.co.identity.features.user.UserRepository;
import istad.co.identity.features.user.UserService;
import istad.co.identity.features.user.dto.UserCreateRequest;
import istad.co.identity.features.user.dto.UserResponse;
import istad.co.identity.mapper.UserMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.*;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;



@Service
@RequiredArgsConstructor
@Slf4j
public class AuthServiceImpl implements AuthService{

    private final PasswordEncoder passwordEncoder;
    private final PasscodeRepository passcodeRepository;
    private final PasscodeService passcodeService;
    private final UserRepository userRepository;
    private final UserService userService;
    private final UserMapper userMapper;
    private final JavaMailSender javaMailSender;
    private final EmailVerificationTokenService emailVerificationTokenService;

    @Override
    public UserResponse register(RegisterRequest registerRequest) {

        UserCreateRequest userCreateRequest = userMapper.mapRegisterRequestToUserCreationRequest(registerRequest);

        userService.checkForPasswords(registerRequest.password(), registerRequest.confirmedPassword());

        userService.checkTermsAndConditions(registerRequest.acceptTerms());

        userService.createNewUser(userCreateRequest);

        return userService.findByUsername(registerRequest.username());
    }

    @Override
    public UserResponse findMe(Authentication authentication) {

        isNotAuthenticated(authentication);

        return userService.findByUsername(authentication.getName());
    }

//    @Override
//    public void changePassword(Authentication authentication, ChangePasswordRequest changePasswordRequest) {
//
//        userService.isNotAuthenticated(authentication);
//
//        userService.checkConfirmPasswords(changePasswordRequest.password(), changePasswordRequest.confirmedPassword());
//
//        userService.checkForOldPassword(authentication.getName(), changePasswordRequest.oldPassword());
//
//        // retrieve user by username from db
//        User user = userRepository.findByUsernameAndIsEnabledTrue(authentication.getName())
//                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User has not been found"));
//
//        user.setPassword(passwordEncoder.encode(changePasswordRequest.password()));
//        userRepository.save(user);
//
//    }

    @Override
    public void isNotAuthenticated(Authentication authentication) {

        if (authentication == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Token is required");
        }

    }
    // TODO forget Password
    @Override
    public void forgotPassword(ForgotPasswordRequest forgotPasswordRequest) {

        User user  = userRepository.findByUsernameAndIsEnabledTrue(forgotPasswordRequest.username()).orElseThrow(()->new ResponseStatusException(HttpStatus.NOT_FOUND,String.format("user not found")));

        Passcode foundToken = passcodeRepository.findByUser(user);

        if(foundToken!=null){
            passcodeRepository.deleteByUser(user);
        }

        passcodeService.generate(user);

    }
    @Override
    public UserResponse login(LoginRequest loginRequest) {
        User user = userRepository.findByUsername(loginRequest.username())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));

        if (!passwordEncoder.matches(loginRequest.password(), user.getPassword())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid password");
        }

        return userMapper.toUserResponse(user);
    }


}
