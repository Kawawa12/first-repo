package org.example.demosecurity;

import org.example.demosecurity.model.Role;
import org.example.demosecurity.model.User;
import org.example.demosecurity.model.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@SpringBootApplication
public class DemoSecurityApplication implements CommandLineRunner {


    private final UserRepository userRepository;

    public DemoSecurityApplication(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public static void main(String[] args) {
        SpringApplication.run(DemoSecurityApplication.class, args);
    }

    @Override
    public void run(String... args) {
        User account = userRepository.findByRole(Role.ADMIN);
        if(null == account) {
            User adminAccount =  new User();
            adminAccount.setName("jackson jackson");
            adminAccount.setEmail("jackson@gmail.com");
            adminAccount.setPassword(new BCryptPasswordEncoder().encode("admin"));
            adminAccount.setRole(Role.ADMIN);
            userRepository.save(adminAccount);
        }
    }
}
