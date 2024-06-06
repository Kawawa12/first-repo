package org.example.demosecurity.controller;

import lombok.RequiredArgsConstructor;
import org.example.demosecurity.dto.RegResponse;
import org.example.demosecurity.service.AuthenticationService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
public class UserController {

    private final AuthenticationService authenticationService;

    @PostMapping("/auth/register")
    public ResponseEntity<RegResponse>  signUp(@RequestBody RegResponse request) {
        return ResponseEntity.ok(authenticationService.signUp(request));
    }

    @GetMapping("/auth/getUsers")
    public ResponseEntity<RegResponse> getAllUsers(){
        return ResponseEntity.ok(authenticationService.findAllUsers());
    }
    
    @PostMapping("/auth/login")
    public ResponseEntity<RegResponse> signIn(RegResponse request) {
        return ResponseEntity.ok(authenticationService.signIn(request));
    }

    @GetMapping("/auth/getUser/{id}")
    public ResponseEntity<RegResponse> getUserById(@PathVariable Integer id) {
        return ResponseEntity.ok(authenticationService.getUserById(id));
    }

    @PutMapping("/auth/editUser/{id}")
    public ResponseEntity<RegResponse> updateUser(@PathVariable Integer id, @RequestBody RegResponse request) {
        return ResponseEntity.ok(authenticationService.updateUser(id,request));
    }

    @DeleteMapping("/auth/delete/{id}")
    public ResponseEntity<RegResponse> deleteUserById(@PathVariable Integer id) {
        return ResponseEntity.ok(authenticationService.deleteUser(id));
    }

    @PostMapping("/auth/refreshToken")
    public ResponseEntity<RegResponse> getRefreshToken(@RequestBody RegResponse request) {
        return ResponseEntity.ok(authenticationService.refreshToken(request));
    }

    @GetMapping("/auth/admin_user/profile")
    public ResponseEntity<RegResponse> getMyInfo() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String email = authentication.getName();
        RegResponse response = authenticationService.getUserInfo(email);
        return ResponseEntity.status(response.getStatusCode()).body(response);
    }
}
