package com.packdev937.securitybasic.config;

import com.packdev937.securitybasic.config.oauth.PrincipalOauth2UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity // 스프링 시큐리티 필터가 스프링 필터 체인에 등록
@RequiredArgsConstructor
public class SecurityConfig { // 기존에는 WebSecurityConfigurerAdapter 클래스를 상속받아서 configure 메서드를 재정의 했어야 됐다.
    // 하지만 이제는 filterChain 메소드를 빈 등록하여 사용한다
    // 추가적으로 WebSecurityConfiguration을 혼동하여 상속하면 에러가 발생한다

    private final PrincipalOauth2UserService principalOauth2UserService;

    private final AuthenticationProvider authenticationProvider;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
            .csrf(csrf -> csrf.disable())
            // csrf은 웹 어플리케이션의 취약점 중 하나로서 사용자의 의도치 않은 요청을 통한 공격을 의미한다
            // 대게 템플릿 엔진을 사용하는 어플리케이션에서 발생
            // 하지만 restAPI에 대해서는 CSRF으로 인한 공격의 위험성이 없기 때문에 disable() 해두어도 무방
            .authorizeRequests(auth -> auth
                .requestMatchers("/user/**").authenticated() // 권한이 필요하다
                .requestMatchers("/manager/**")
                .access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')") // 접근 권한이 필요하다
                .requestMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll()) // 그 외 경로는 모두 허용한다
            .formLogin(f -> f
                .loginPage("/login") // Q. 여기서 loginForm의 역할
                .loginProcessingUrl("/login")
                .defaultSuccessUrl("/"))
            .oauth2Login(o -> o
                .loginPage("/login")
                .userInfoEndpoint(u -> u
                    .userService(principalOauth2UserService))) // 구글 로그인이 된 후 후처리가 진행되어야 한다
            .httpBasic(Customizer.withDefaults())
            // httpBasic() : 사용자는 HTTP 기반 인증으로 인증할 수 있다.
            // 기존의 웹 html 에서 거쳐야 했던 인증 절차를 팝업을 통하여 인증절차를 거치도록 수정 (Rest API에서 웹 형식은 맞지 않기 때문)
            .build();
        // access(String) : 주어진 spEL 표현식의 평가 결과가 true 면 접근을 허용한다
        // authenticated() : 인증된 사용자의 접근을 허용한다
        // anonymous() : 익명의 사용자의 접근을 허용한다
        // hasRole(String) : 사용자가 주어진 역할이 있다면 접근을 허용한다
        // hasAnyRole(String) : 사용자가 주어진 역할 중 어떤 것이라도 있다면 접근을 허용한다
        // permitAll() : 무조건 접근을 허용한다
        // denyAll() : 무조건 접근을 허용하지 않는다
    }
}

// 추가 속성 정리
// .formLogin() : 사용자는 폼 기반 로그인으로 인증할 수 있다.
// .loginPage("/login") : 로그인 페이지 URL은 "/login" 이다 (로그인 페이지의 디폴드 값은 POST 방식의 /login 이다)
// .defaultSuccessURL("/home", true) : 로그인 성공 시 "/home" 으로 이동한다
// .logoutUrl("/logout") : "/logout"이 요청되면 로그아웃 한다.
// .logoutSuccessUrl("/home")
// .failureUrl("/login.html?error=true") : 로그인 실패 후 이동 페이지
// .usernameParameter("username") : 아이디 파라미터명 설정
// .passwordParameter("password") : 패스워드 파라미터명 설정
// .loginProcessingUrl("/login")  : 로그인 Form Action Url

// 추가 정보 정리
// 별다른 설정사항을 수정하지 않는다면 username = user, password = 실행 시 생성되는 security password