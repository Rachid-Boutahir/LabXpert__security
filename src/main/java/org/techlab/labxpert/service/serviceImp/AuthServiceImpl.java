package org.techlab.labxpert.service.serviceImp;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;

import org.techlab.labxpert.dtos.LoginDto;
import org.techlab.labxpert.dtos.RegisterDto;
import org.techlab.labxpert.entity.Utilisateur;
import org.techlab.labxpert.exception.BlogAPIException;
import org.techlab.labxpert.service.I_AuthService;
import org.techlab.labxpert.repository.UtilisateurRepository;

import java.util.HashSet;
import java.util.Set;

@Service
public class AuthServiceImpl implements I_AuthService {

    private AuthenticationManager authenticationManager;
    private UtilisateurRepository utilisateurRepository;
    private PasswordEncoder passwordEncoder;


    @Override
    public String login(LoginDto loginDto) {
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                loginDto.getUsernameOrEmail(), loginDto.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);

        String token = jwtTokenProvider.generateToken(authentication);

        return token;
    }

    @Override
    public String register(RegisterDto registerDto) {

        // add check for username exists in database
        if (userRepository.existsByUsername(registerDto.getUsername())) {
            throw new BlogAPIException(HttpStatus.BAD_REQUEST, "Username is already exists!.");
        }

        // add check for email exists in database
        if (userRepository.existsByEmail(registerDto.getEmail())) {
            throw new BlogAPIException(HttpStatus.BAD_REQUEST, "Email is already exists!.");
        }

        Utilisateur user = new Utilisateur();
        user.setNom(registerDto.getName());
        user.setNomUtilisateur(registerDto.getUsername());
        user.setEmail(registerDto.getEmail());
        user.setPassword(passwordEncoder.encode(registerDto.getPassword()));
        user.setRole(registerDto.getRole());
        userRepository.save(user);

        return "User registered successfully!.";
    }
}
