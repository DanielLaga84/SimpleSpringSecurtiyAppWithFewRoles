package com.example.studentsapi.auth;


import org.springframework.stereotype.Controller;

import java.util.Optional;


public interface ApplicationUserDao {

     Optional<ApplicationUser> selectApplicationUserByUsername(String username);

}
