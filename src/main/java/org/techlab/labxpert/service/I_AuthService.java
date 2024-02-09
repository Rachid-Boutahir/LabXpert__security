package org.techlab.labxpert.service;

import org.techlab.labxpert.dtos.LoginDto;
import org.techlab.labxpert.dtos.RegisterDto;

public interface I_AuthService {
    String login(LoginDto loginDto);

    String register(RegisterDto registerDto);
}
