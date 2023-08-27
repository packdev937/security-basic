package com.packdev937.securitybasic.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.packdev937.securitybasic.config.auth.PrincipalDetails;
import com.packdev937.securitybasic.entity.User;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
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
            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                user.getUsername(), user.getPassword());

            // PrincipalDetailsService의 loadUserByUsername()이 실행됨
            // token을 통해서 로그인 시도르 해보고 된다면 authentication 객체가 반환
            // 된다는건 DB에 있는 username과 password가 일치
            // authentication에 내 로그인 정보가 담김
            Authentication authentication = authenticationManager.authenticate(authenticationToken);

            // authetnication 객체가 session 영역에 저장되어야하고 이는 반환을 통해 이루어짐
            // 리턴의 이유는 권한 관리를 security가 대신 해주기 때문에
            // 굳이 JWT 토큰을 사용하면서 세션을 만들 이유는 없지만 권한 처리 떄문에 Session에 넣음

            // JWT Token은 여기서 안 만들어도 됨
            // 이 함수가 종료되면 뒤에 실행되는 함수가 있음 -> successfulAuthentication
            // 실행되는 순서가 attemptAuthentication -> successfulAuthentication
            // successful에서 JWT 토큰을 만들고 request 요청한 사용자에게 JWT 토큰을 response 해주면 됨
            return authentication;
        } catch (IOException e) {
            e.getMessage();
        }
        // 2. 정상인지 로그인 시도를 해본다
        // authenticationManager로 로그인 시도를 하면 PrincipalDetailsService가 호출된다
        // loadUserByUsername이 자동으로 실행된다
        // 3. PrincipalDetails를 세션에 담고
        // 굳이 세션에 담는 이유는 권한 권리를 하기 위해
        // 만약 권한 관리를 하지 않는다면 이를 담을 필요가 없다
        // 4. JWT 토큰을 만들어서 응답해준다
        return null;
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request,
        HttpServletResponse response, FilterChain chain, Authentication authResult)
        throws IOException, ServletException {

        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        // HMAC 방식 -> 특징 시크릿 키를 알고 있어야 함
        String jwtToken = JWT.create()
            .withSubject(principalDetails.getUsername()) // Token 이름
            .withExpiresAt(new Date(System.currentTimeMillis() + (60000 * 10)))
            // 비공개 클레임 -> 넣고 싶은 key:value를 넣으면 됨
            .withClaim("id", principalDetails.getUser().get().getId())
            .withClaim("username", principalDetails.getUser().get().getUsername())
            .sign(Algorithm.HMAC256("auth")); // 시크릿은 내 서버만 알고 있는 고유한 값

        // Bearer에서 한칸 띄어야됨
        response.addHeader("Authorization", "Bearer "+jwtToken);
    }
}
