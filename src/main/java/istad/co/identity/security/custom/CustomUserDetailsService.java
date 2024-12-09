package istad.co.identity.security.custom;

import istad.co.identity.domain.User;
import istad.co.identity.features.user.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String usernameOrEmail) throws UsernameNotFoundException {
        log.info("Attempting to load user: {}", usernameOrEmail);

        User user = userRepository.findByUsernameOrEmailAndIsEnabledTrue(usernameOrEmail, usernameOrEmail)
                .orElseThrow(() -> {
                    log.warn("User not found with identifier: {}", usernameOrEmail);
                    return new UsernameNotFoundException("User not found");
                });

        log.info("Successfully loaded user: {}", user.getUsername());
        return new CustomUserDetails(user);
    }
}