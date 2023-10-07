package com.santechture.api.service;

import com.santechture.api.dto.GeneralResponse;
import com.santechture.api.dto.admin.AdminDto;
import com.santechture.api.entity.Admin;
import com.santechture.api.exception.BusinessExceptions;
import com.santechture.api.repository.AdminRepository;
import com.santechture.api.security.JwtTokenUtil;
import com.santechture.api.validation.LoginRequest;
import io.jsonwebtoken.Clock;
import io.jsonwebtoken.impl.DefaultClock;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.Objects;

@Service
public class AdminService {


private final JwtTokenUtil jwtTokenUtil;
    private final AdminRepository adminRepository;


    public AdminService(JwtTokenUtil jwtTokenUtil, AdminRepository adminRepository) {
        this.jwtTokenUtil = jwtTokenUtil;
        this.adminRepository = adminRepository;
    }

    public ResponseEntity<GeneralResponse> login(LoginRequest request) throws BusinessExceptions {

        Admin admin = adminRepository.findByUsernameIgnoreCase(request.getUsername());

        if(Objects.isNull(admin) || !admin.getPassword().equals(request.getPassword())){
            throw new BusinessExceptions("login.credentials.not.match");
        }
        String token =jwtTokenUtil.generateToken(admin);
        return new GeneralResponse().response(new AdminDto(admin,token));
    }
    public void logOutCurrentAdmin()
    {
        Clock clock = DefaultClock.INSTANCE;

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        Admin admin=adminRepository.findByUsernameIgnoreCase(auth.getName());
        admin.setLastLogOut(clock.now());
        adminRepository.save(admin);
    }
}
