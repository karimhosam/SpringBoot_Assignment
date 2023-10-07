package com.santechture.api.dto.admin;

import com.santechture.api.entity.Admin;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.Basic;
import javax.persistence.Column;

@AllArgsConstructor
@NoArgsConstructor
@Data
public class AdminDto {

    private Integer adminId;

    private String username;
    private String token;

    public AdminDto(Admin admin){
        setAdminId(admin.getAdminId());
        setUsername(admin.getUsername());
    }

    public AdminDto(Admin admin,String token){
        setAdminId(admin.getAdminId());
        setUsername(admin.getUsername());
        setToken(token);
    }

}
