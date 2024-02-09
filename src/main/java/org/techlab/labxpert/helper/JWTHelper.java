package org.techlab.labxpert.helper;

import com.auth0.jwt.algorithms.Algorithm;
import org.springframework.stereotype.Component;

import java.util.Map;

import static org.techlab.labxpert.constant.JWTUtil.SECRET;

@Component
public class JWTHelper {

    //    Algorithm algorithm = Algorithm.HMAC256(SECRET);
    Algorithm algorithm = Algorithm.HMAC256(SECRET);

    public String generateAccessToken() {
        return null;
    }

    public String generateRefreshToken() {
        return null;
    }

    public String extractTokenFromHeaderIfExists() {
        return null;

    }

    public Map<String, String> getTokensMap() {
        return null;
    }
}
