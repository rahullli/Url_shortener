package com.url.url_shortner.models;

import jakarta.persistence.*;
import lombok.Data;

@Entity
@Data
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY) // Auto generated value.
    private Long id;

    private String email;
    private String userName;
    private String passWord;
    private String role = "ROLE_USER";

}
