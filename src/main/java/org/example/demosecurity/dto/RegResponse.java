package org.example.demosecurity.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;
import org.example.demosecurity.model.User;

import java.util.List;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class RegResponse {

    private String firstName;
    private String lastName;
    private String email;
    private String password;

    private String token;
    private String refreshToken;
    private int statusCode;
    private String error;
    private String expirationTime; 
    private String message;

    private User user;
    private List<User> userLists;

}
