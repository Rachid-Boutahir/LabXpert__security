package org.techlab.labxpert.constant;

public class JWTUtil {
    private static final long EXPIRE_ACCESS_TOKEN = 1*60*1000;
    public static final long EXPIRE_REFRESH_TOKEN = 120*60*1000;

    public static final String BEARER_PREFIX= "Bearer ";

    public static final String ISSUER = "springBootApp";

    public static final String SECRET ="DYb&lRD%PMX0PC^|1P#Yh1f+hUMPkMw<{RM4fFWXb5f`]=brC.dJKG]'aAfRL6/";
    // public static final String SECRET ="myPrivateSecret";

    public static final String AUTH_HEADER = "Authorization";

}
