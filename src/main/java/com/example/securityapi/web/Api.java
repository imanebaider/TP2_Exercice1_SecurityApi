package com.example.securityapi.web;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
public class Api {

    private AuthenticationManager authenticationManager;
    private JwtEncoder jwtEncoder;
    private JwtDecoder jwtDecoder;

    private UserDetailsService  userDetailsService;

    public Api(AuthenticationManager authenticationManager, JwtEncoder jwtEncoder, JwtDecoder jwtDecoder, UserDetailsService userDetailsService) {
        this.authenticationManager = authenticationManager;
        this.jwtEncoder = jwtEncoder;
        this.jwtDecoder = jwtDecoder;
        this.userDetailsService = userDetailsService;
    }

    @PostMapping("/login")
    Map<String,String> login(String username, String password){

        Map<String,String>  ID_token = new HashMap<>();
        Instant  instant =Instant.now();
        // verifier l'authentification
        Authentication authenticate = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(username, password)
        );

        // get scope
        String scope = authenticate.getAuthorities().stream().map(auth-> auth.getAuthority()).collect(Collectors.joining(" "));

        // création des ID Token
        //1 -Acess token

        JwtClaimsSet jwtClaimsSet_acessToken = JwtClaimsSet.builder()
                .subject(authenticate.getName())
                .issuer("Security_Service")
                .issuedAt(instant)
                .expiresAt(instant.plus(2, ChronoUnit.MINUTES))
                .claim("scope",scope)
                .build();

        String Access_token = jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet_acessToken)).getTokenValue();

        // refresh token

        JwtClaimsSet jwtClaimsSet_refreshToken = JwtClaimsSet.builder()
                .subject(authenticate.getName())
                .issuer("Security_Service")
                .issuedAt(instant)
                .expiresAt(instant.plus(15, ChronoUnit.MINUTES))
                .build();

        String Refresh_token = jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet_refreshToken)).getTokenValue();

        ID_token.put("Access_Token",Access_token);
        ID_token.put("Refresh_Token",Refresh_token);
        return ID_token;
    }


    @PostMapping("/refresh")
    public Map<String,String> refresh( String refreshToken){

        Map<String,String> ID_Token= new HashMap<>();

        if (refreshToken == null){
            ID_Token.put("Error","Refresh token est null"+ HttpStatus.UNAUTHORIZED);
            return ID_Token;
        }

        // verifier signature
        Jwt decoded = jwtDecoder.decode(refreshToken);

        String usermane = decoded.getSubject();

        UserDetails userDetails = userDetailsService.loadUserByUsername(usermane);

        Instant instant = Instant.now();
        // creation Access Token

        // get scope
        String scope = userDetails.getAuthorities().stream().map(auth-> auth.getAuthority()).collect(Collectors.joining(" "));

        // création des ID Token
        //1 -Acess token
        JwtClaimsSet jwtClaimsSet_acessToken = JwtClaimsSet.builder()
                .subject(userDetails.getUsername())
                .issuer("Security_Service")
                .issuedAt(instant)
                .expiresAt(instant.plus(2, ChronoUnit.MINUTES))
                .claim("scope",scope)
                .build();

        String Access_token = jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet_acessToken)).getTokenValue();

        ID_Token.put("Access_Token",Access_token);
        ID_Token.put("Refresh_Token",refreshToken);
        return ID_Token;


    }












}