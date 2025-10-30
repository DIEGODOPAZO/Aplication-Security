package es.storeapp.business.repositories;

import es.storeapp.business.entities.User;
import jakarta.persistence.NoResultException;
import jakarta.persistence.TypedQuery;
import org.springframework.stereotype.Repository;

@Repository
public class UserRepository extends AbstractRepository<User> {

    private static final String FIND_USER_BY_EMAIL_QUERY =
            "SELECT u FROM User u WHERE u.email = :email";

    private static final String COUNT_USER_BY_EMAIL_QUERY =
            "SELECT COUNT(u) FROM User u WHERE u.email = :email";

    private static final String LOGIN_QUERY =
            "SELECT u FROM User u WHERE u.email = :email AND u.password = :password";

    public User findByEmail(String email) {
        try {
            TypedQuery<User> query = entityManager.createQuery(FIND_USER_BY_EMAIL_QUERY, User.class);
            query.setParameter("email", email);
            return query.getSingleResult();
        } catch (NoResultException e) {
            logger.debug("No user found for email {}", email);
            return null;
        }
    }

    public boolean existsUser(String email) {
        TypedQuery<Long> query = entityManager.createQuery(COUNT_USER_BY_EMAIL_QUERY, Long.class);
        query.setParameter("email", email);
        return query.getSingleResult() > 0;
    }

    public User findByEmailAndPassword(String email, String password) {
        try {
            TypedQuery<User> query = entityManager.createQuery(LOGIN_QUERY, User.class);
            query.setParameter("email", email);
            query.setParameter("password", password);
            return query.getSingleResult();
        } catch (NoResultException e) {
            logger.debug("Invalid login attempt for email {}", email);
            return null;
        }
    }
}
