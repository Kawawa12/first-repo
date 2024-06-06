package org.example.demosecurity.service;

import lombok.RequiredArgsConstructor;
import org.example.demosecurity.dto.RegResponse;
import org.example.demosecurity.model.Role;
import org.example.demosecurity.model.User;
import org.example.demosecurity.model.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthenticationService implements AuthResponse {

    private final UserRepository userRepository;
    private final JWTService jwtService;
    private final AuthenticationManager authenticationManager;
    private final PasswordEncoder passwordEncoder;

    //Registration handling
    public RegResponse signUp(RegResponse request) {

        RegResponse response = new RegResponse();

        try {
            User user = new User();
            user.setName(request.getFirstName() + " " + request.getLastName());
            user.setEmail(request.getEmail());
            user.setPassword(passwordEncoder.encode(request.getPassword())); // Ensure password is encoded
            user.setRole(Role.USER);
            User savedUser = userRepository.save(user);

            if (savedUser.getId() > 0) {
                response.setStatusCode(200);
                response.setUser(savedUser);
                response.setMessage("User saved successfully!");
            } else {
                response.setMessage("Something went wrong!, user not saved!");
            }

        } catch (Exception e) {
            response.setStatusCode(500);
            response.setError(e.getMessage());
        }
        return response;
    }

    // Login handling
    public RegResponse signIn(RegResponse request) {
        RegResponse response = new RegResponse();
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));
            User user = userRepository.findByEmail(request.getEmail()).orElseThrow();
            String jwtToken = jwtService.generateToken(user);
            String refreshJwtToken = jwtService.generateRefreshToken(new HashMap<>(), user);

            response.setToken(jwtToken);
            response.setRefreshToken(refreshJwtToken);
            response.setExpirationTime("24Hrs");
            response.setStatusCode(200);
            response.setMessage("Login successfully!");

        } catch (Exception e) {
            response.setStatusCode(500);
            response.setError(e.getMessage());
        }
        return response;
    }

    // Refresh token handling method
    public RegResponse refreshToken(RegResponse request) {
        RegResponse response = new RegResponse();
        try {
            String email = jwtService.extractUsername(request.getToken());
            User user = userRepository.findByEmail(email).orElseThrow();
            if (jwtService.isTokenValid(request.getToken(), user)) {
                String refToken = jwtService.generateToken(user);

                response.setStatusCode(200);
                response.setToken(refToken);
                response.setRefreshToken(request.getToken());
                response.setExpirationTime("24Hrs");
                response.setMessage("Token refreshed successfully!");
            } else {
                response.setStatusCode(400);
                response.setMessage("Invalid token!");
            }
        } catch (Exception e) {
            response.setStatusCode(500);
            response.setError(e.getMessage());
        }
        return response;
    }

    // Find all users
    public RegResponse findAllUsers() {
        RegResponse response = new RegResponse();

        try {
            List<User> allUsers = userRepository.findAll();
            if (!allUsers.isEmpty()) {
                response.setUserLists(allUsers);
                response.setStatusCode(200);
                response.setMessage("Successfully retrieved users!");
            } else {
                response.setMessage("No users found!");
                response.setStatusCode(404);
            }
        } catch (Exception e) {
            response.setStatusCode(500);
            response.setError(e.getMessage());
        }
        return response;
    }

    // Update user
    public RegResponse updateUser(int userId, RegResponse updatedUser) {
        RegResponse response = new RegResponse();

        try {
            Optional<User> optionalUser = userRepository.findById(userId);

            if (optionalUser.isPresent()) {
                User existingUser = optionalUser.get();
                existingUser.setName(updatedUser.getFirstName() + " " + updatedUser.getLastName());
                existingUser.setEmail(updatedUser.getEmail());

                // Check if request contains password which is not null and not empty
                if (updatedUser.getPassword() != null && !updatedUser.getPassword().isEmpty()) {
                    // Encode password
                    existingUser.setPassword(passwordEncoder.encode(updatedUser.getPassword()));
                }

                User savedUpdatedUser = userRepository.save(existingUser);

                if (savedUpdatedUser.getId() > 0) {
                    response.setUser(savedUpdatedUser);
                    response.setStatusCode(200);
                    response.setMessage("User updated successfully!");
                } else {
                    response.setStatusCode(403);
                    response.setMessage("User not found for update!");
                }
            } else {
                response.setStatusCode(404);
                response.setMessage("User not found!");
            }
        } catch (Exception e) {
            response.setStatusCode(500);
            response.setError("User not updated! " + e.getMessage());
        }
        return response;
    }

    // Delete user
    public RegResponse deleteUser(int userId) {
        RegResponse response = new RegResponse();
        try {
            Optional<User> optionalUser = userRepository.findById(userId);
            if (optionalUser.isPresent()) {
                userRepository.deleteById(userId);
                response.setStatusCode(200);
                response.setMessage("User deleted successfully!");
            } else {
                response.setStatusCode(404);
                response.setMessage("User not found!");
            }
        } catch (Exception e) {
            response.setStatusCode(500);
            response.setError("Something went wrong on deleting user " + e.getMessage());
        }
        return response;
    }

    // Get user information
    public RegResponse getUserInfo(String email) {
        RegResponse response = new RegResponse();

        try {
            Optional<User> optionalUserInfo = userRepository.findByEmail(email);
            if (optionalUserInfo.isPresent()) {
                response.setUser(optionalUserInfo.get());
                response.setStatusCode(200);
                response.setMessage("User information retrieved successfully!");
            } else {
                response.setStatusCode(403);
                response.setMessage("No user information found!");
            }
        } catch (Exception e) {
            response.setStatusCode(500);
            response.setError("Error! Information not retrieved " + e.getMessage());
        }
        return response;
    }

    //Get user by id
    public RegResponse getUserById(Integer userId){
        RegResponse response = new RegResponse();

        try{
            User user = userRepository.findById(userId).orElseThrow(() -> new
                     IllegalArgumentException("User with ID "+ userId + " not found!"));
             response.setUser(user);
             response.setStatusCode(200);
             response.setMessage("User with Id " + userId + " found successfully!");

        }catch (Exception e) {
            response.setStatusCode(500);
            response.setMessage("User with Id " + userId + " is not found!");
        }

        return response;
    }
}
