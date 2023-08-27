package com.packdev937.securitybasic.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.packdev937.securitybasic.entity.User;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;

    // /login 요청을 하면 로그인 시도를 위해서 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
        HttpServletResponse response) throws AuthenticationException {
        // 1. 아이디, 비밀번호를 받아서
            // request.getInputStream() byte 안에 username과 password가 담겨있다.
//        try {
//            BufferedReader br = request.getReader();
//
//            String input = null;
//            while((input = br.readLine()) != null){
//                System.out.println(input);
//            }
//        } catch (IOException e){
//            e.getMessage();
//        }
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            User user = objectMapper.readValue(request.getInputStream(), User.class);

            // Token 생성
            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            // PrincipalDetailsService의 loadUserByUsername()이 실행됨
            // authentication에 내 로그인 정보가 담김
            Authentication authentication = authenticationManager.authenticate(authenticationToken);

            // authetnication 객체가 session 영역에 저장되었다는 건 로그인이 되었다는 걸 의미
        } catch (IOException e){
            e.getMessage();
        }
        // 2. 정상인지 로그인 시도를 해본다
        // authenticationManager로 로그인 시도를 하면 PrincipalDetailsService가 호출된다
        // loadUserByUsername이 자동으로 실행된다
        // 3. PrincipalDetails를 세션에 담고
        // 굳이 세션에 담는 이유는 권한 권리를 하기 위해
        // 만약 권한 관리를 하지 않는다면 이를 담을 필요가 없다
        // 4. JWT 토큰을 만들어서 응답해준다
        return super.attemptAuthentication(request, response);
    }
}
