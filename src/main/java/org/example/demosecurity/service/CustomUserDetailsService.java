package org.example.demosecurity.service;

import org.example.demosecurity.model.UserRepository;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsService implements UserService{

    private final UserRepository userRepository;

    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetailsService UserDetailsService() {
        return username -> userRepository.findByEmail(username).orElseThrow(()-> new
                UsernameNotFoundException("User not found!"));
    }
}
