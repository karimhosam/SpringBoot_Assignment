package com.santechture.api.security;

import com.santechture.api.dto.admin.JwAdmin;
import com.santechture.api.entity.Admin;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Clock;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.DefaultClock;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Component
public class JwtTokenUtil {
    String secret="secretKey";

    private Clock clock = DefaultClock.INSTANCE;

    private Date calculateExpirationDate(Date createdDate) {
        return new Date(createdDate.getTime() + 3600000);
    }

    public String generateToken(Admin admin) {
        final Date createdDate = clock.now();
        System.out.println("date: "+createdDate.toString());
        Map<String, Object> payload = new HashMap<>();
        payload.put("userName", admin.getUsername());
        payload.put("id", admin.getAdminId());
        return Jwts.builder().setClaims(payload).setIssuedAt(createdDate)
                .setExpiration(calculateExpirationDate(createdDate))
                .signWith(SignatureAlgorithm.HS512, secret)
                .compact();
    }
    public Claims getAllClaimsFromToken(String token) {
        return Jwts.parser()
                .setSigningKey(secret)
                .parseClaimsJws(token)
                .getBody();
    }
    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        System.out.println("---getClaimFromToken---");
        final Claims claims = getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }
    public Date getExpirationDateFromToken(String token) {
        System.out.println("---getExpirationDateFromToken---");
        return getClaimFromToken(token, Claims::getExpiration);
    }
    public Date getIssuedAtDateFromToken(String token) {
        System.out.println("---getIssuedAtDateFromToken---");
        return getClaimFromToken(token, Claims::getIssuedAt);
    }

    private Boolean isTokenExpired(String token) {
        System.out.println("---isTokenExpired---");
        final Date expiration = getExpirationDateFromToken(token);
        return expiration.before(clock.now());
    }
    private Boolean isTokenCreatedAfterLastLogOut(String token, JwAdmin admin)
    {
        final Date issuedAt = getIssuedAtDateFromToken(token);
        if(admin.getLastLogOut()==null)
            return true;
        return admin.getLastLogOut().before(issuedAt);
    }
    public Boolean validateToken(String token, UserDetails userDetails)
    {
        JwAdmin admin= (JwAdmin) userDetails;
        return (!isTokenExpired(token)&& isTokenCreatedAfterLastLogOut(token,admin));

    }

}
