package es.storeapp.business.repositories;

import es.storeapp.business.entities.Order;
import java.text.MessageFormat;
import java.util.List;
import java.util.Optional;

import jakarta.persistence.Query;
import org.springframework.stereotype.Repository;

@Repository
public class OrderRepository extends AbstractRepository<Order> {
    private static final String FIND_BY_USER_QUERY = 
            "SELECT o FROM Order o WHERE o.user.id = {0} ORDER BY o.timestamp DESC";
        
    @SuppressWarnings("unchecked")
    public List<Order> findByUserId(Long userId) {
        Query query = entityManager.createQuery(MessageFormat.format(FIND_BY_USER_QUERY, userId));
        return (List<Order>) query.getResultList();
    }

    public Optional<Order> findByIdAndUserId(Long id, Long userId) {
        return entityManager.createQuery(
                        "SELECT o FROM Order o WHERE o.orderId = :id AND o.user.userId = :userId",
                        Order.class
                )
                .setParameter("id", id)
                .setParameter("userId", userId)
                .getResultList()
                .stream()
                .findFirst();
    }
   
}
