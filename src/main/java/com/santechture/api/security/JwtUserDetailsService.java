package com.santechture.api.security;

import com.santechture.api.dto.admin.JwAdmin;
import com.santechture.api.entity.Admin;
import com.santechture.api.repository.AdminRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;

@Service
public class JwtUserDetailsService implements UserDetailsService {

    @Autowired
    private AdminRepository adminRepository;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
       Admin admin= adminRepository.findByUsernameIgnoreCase(username);
        if(admin!=null)
            return new JwAdmin(admin);
        return null;
    }
}
