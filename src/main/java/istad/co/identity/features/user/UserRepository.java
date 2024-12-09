package istad.co.identity.features.user;

import istad.co.identity.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByUsername(String username);

    Optional<User> findByUsernameAndIsEnabledTrue(String username);

    Optional<User> findByUsernameAndIsEnabledFalse(String username);

    Optional<User> findByUsernameAndPasswordAndIsEnabledTrue(String username, String password);

    Optional<User> findByEmail(String email);

    Optional<User> findByEmailAndPasswordAndIsEnabledTrue(String email, String password);

//    List<User> findAllByFamilyNameContainsOrGivenNameContainsOrUsernameContains(String firstName, String lastName, String username);

    boolean existsByUsername(String username);

    boolean existsByEmail(String email);
    @Query("SELECT u FROM User u WHERE (u.username = :identifier OR u.email = :identifier) AND u.isEnabled = true")
    Optional<User> findByUsernameOrEmailAndIsEnabledTrue(
            @Param("identifier") String identifier,
            @Param("identifier") String sameIdentifier
    );

    // Optional: Add method to find by either username or email without enabled check
    @Query("SELECT u FROM User u WHERE u.username = :identifier OR u.email = :identifier")
    Optional<User> findByUsernameOrEmail(
            @Param("identifier") String identifier,
            @Param("identifier") String sameIdentifier
    );
}
