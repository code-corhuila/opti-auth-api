package co.edu.corhuila.opti.auth.application.usecase;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import co.edu.corhuila.opti.auth.application.port.in.NotificationUseCases;
import co.edu.corhuila.opti.auth.application.port.in.PageQuery;
import co.edu.corhuila.opti.auth.domain.model.DomainException;
import co.edu.corhuila.opti.auth.domain.model.ErrorKind;
import co.edu.corhuila.opti.auth.domain.model.FieldError;
import co.edu.corhuila.opti.auth.domain.model.Notification;
import co.edu.corhuila.opti.auth.domain.model.NotificationType;
import co.edu.corhuila.opti.auth.testsupport.DirectUnitOfWork;
import co.edu.corhuila.opti.auth.testsupport.InMemoryIdempotencyStore;
import co.edu.corhuila.opti.auth.testsupport.InMemoryNotifications;
import co.edu.corhuila.opti.auth.testsupport.SequentialIds;
import co.edu.corhuila.opti.auth.testsupport.TestClock;

class NotificationServiceTest {

    private static final UUID SELLER = UUID.fromString("22222222-2222-4222-8222-222222222222");
    private static final UUID OTHER = UUID.fromString("33333333-3333-4333-8333-333333333333");

    private NotificationUseCases service;

    @BeforeEach
    void setUp() {
        var clock = TestClock.at("2026-10-01T08:00:00Z");
        var keys = new InMemoryIdempotencyStore();
        service = new NotificationService(new InMemoryNotifications(), keys, new SequentialIds(),
                new DirectUnitOfWork(keys), clock);
    }

    @Test
    void createsANotificationForTheSeller() {
        var created = service.create(data(), "goal-2026-10-0001");

        assertThat(created.created()).isTrue();
        assertThat(service.mine(SELLER, PageQuery.first(10)).total()).isEqualTo(1);
    }

    @Test
    void repeatingTheKeyWithinThePeriodCreatesNothingTwice() {
        var first = service.create(data(), "goal-2026-10-0001");
        var second = service.create(data(), "goal-2026-10-0001");

        assertThat(second.created()).isFalse();
        assertThat(second.value().id()).isEqualTo(first.value().id());
        assertThat(service.mine(SELLER, PageQuery.first(10)).total()).isEqualTo(1);
    }

    @Test
    void aSellerSeesOnlyTheirOwnNotifications() {
        service.create(data(), "goal-2026-10-0001");

        assertThat(service.mine(OTHER, PageQuery.first(10)).total()).isZero();
    }

    @Test
    void markingSomeoneElsesNotificationReadIsNotFound() {
        var created = service.create(data(), "goal-2026-10-0001").value();

        assertThatThrownBy(() -> service.markRead(created.id(), OTHER))
                .isInstanceOfSatisfying(DomainException.class,
                        e -> assertThat(e.kind()).isEqualTo(ErrorKind.NOT_FOUND));
    }

    @Test
    void markingItReadTwiceIsHarmless() {
        var created = service.create(data(), "goal-2026-10-0001").value();

        var read = service.markRead(created.id(), SELLER);
        var again = service.markRead(created.id(), SELLER);

        assertThat(read.readAt()).isNotNull();
        assertThat(again.readAt()).isEqualTo(read.readAt());
    }

    @Test
    void reportsEveryInvalidFieldAtOnce() {
        assertThatThrownBy(() -> service.create(new Notification.Data(null, null, " "), "short"))
                .isInstanceOfSatisfying(DomainException.class, e -> {
                    assertThat(e.kind()).isEqualTo(ErrorKind.VALIDATION);
                    assertThat(e.fields()).extracting(FieldError::field)
                            .containsExactlyInAnyOrder("Idempotency-Key", "userId", "type", "message");
                });
    }

    private static Notification.Data data() {
        return new Notification.Data(SELLER, NotificationType.SALES_GOAL_REACHED,
                "Alcanzaste tu meta de ventas de octubre.");
    }
}
