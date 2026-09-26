package co.edu.corhuila.opti.auth.app;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/** Entry point of the auth service. */
@SpringBootApplication(scanBasePackages = "co.edu.corhuila.opti.auth")
public class AuthApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthApplication.class, args);
    }
}
