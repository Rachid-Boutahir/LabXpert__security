package org.techlab.labxpert.controllers;

import net.sf.jasperreports.ant.JRAntApiWriteTask;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import org.techlab.labxpert.dtos.LoginDto;
import org.techlab.labxpert.dtos.RegisterDto;
import org.techlab.labxpert.payload.JWTAuthResponse;
import org.techlab.labxpert.service.I_AuthService;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    //TODO:1-creer le service AuthService dans le dossier service et l'implementer le code.
    //TODO:2-injecter le dans AuthController dans le controleur
    private I_AuthService authService;

    public AuthController(I_AuthService authService) {
        this.authService = authService;
    }


    // Build Login REST API
    @PostMapping(value = {"/login", "/signin"})
    public ResponseEntity<JWTAuthResponse> login(@RequestBody LoginDto loginDto) {

        String accessToken = authService.login(loginDto);
        JWTAuthResponse jwtAuthResponse = new JWTAuthResponse();
        jwtAuthResponse.setAccessToken(accessToken);
        return ResponseEntity.ok(jwtAuthResponse);

    }

    // Build Register REST API
    @PostMapping(value = {"/register", "/signup"})
    public ResponseEntity<String> register(@RequestBody RegisterDto registerDto) {

        String response = authService.register(registerDto);
        return new ResponseEntity<>(response, HttpStatus.CREATED);

    }

}
