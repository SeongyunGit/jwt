package jwt.jwt.service;

import jwt.jwt.jwttoken.JwtToken;

public interface MemberService {
    JwtToken signIn(String username, String password);
}
