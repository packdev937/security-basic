package com.packdev937.securitybasic.controller;

import com.packdev937.securitybasic.config.auth.PrincipalDetails;
import com.packdev937.securitybasic.entity.User;
import com.packdev937.securitybasic.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@RequiredArgsConstructor
public class IndexController {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    // @Authentication 어노테이션을 통해 세션 정보에 접근할 수 있음
    // @Authentication은 UserDetails 타입을 가지고 있음 -> PrincipalDetails 가 UserDetails를 Implement 함

    @GetMapping("/test/login")
    public @ResponseBody String testLogin(Authentication authentication,
                                          @AuthenticationPrincipal PrincipalDetails userDetails) // 의존성 주입
    {
        // 일반 로그인은 되는데 Oauth는 오류가 남
        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
        System.out.println("authentication: " + principalDetails.getUser()); // 첫 번째 방법 (다운 캐스팅)
        System.out.println("userDetails: " + userDetails.getUser()); // 두 번째 방법
        return "세션 정보 확인하기";
    }

    @GetMapping("/test/oauth/login")
    public @ResponseBody String testOAuthLogin(Authentication authentication,
                                               @AuthenticationPrincipal OAuth2User oauth) {
        // 근데 PrincipalDetails 는 구현했는데, OAuth2User는 우리가 딱히 작성안해도 되는가?
        // 원래 위에도 UserDetails로 받는다. 근데 PrincipalDetails는 UserDetails를 상속했기 때문에 가능
        // 얘는 OAuth2User로 받아야 함
        OAuth2User principalDetails = (OAuth2User) authentication.getPrincipal(); // 다운 캐스팅
        System.out.println("authentication: " + principalDetails.getAttributes()); // 첫 번째 방법
        System.out.println("oauth2User: " + oauth.getAttributes());
        return "OAuth 세션 정보 확인하기";
    }

    @GetMapping({"", " "})
    public String index() {
        return "index";
    }

    // message 창에 default username, password를 입력하면 넘어가짐
    // 일반 로그인이면 PrincipalDetails 근데 소셜 로그인에서는 Oauth2User를 넣어야 함
    @GetMapping("/user")
    public @ResponseBody String user(@AuthenticationPrincipal PrincipalDetails userDetails) {
        return "user";
    }

    @GetMapping("/manager")
    public @ResponseBody String manager() {
        return "manager";
    }

    @GetMapping("/admin")
    public @ResponseBody String admin() {
        return "admin";
    }

    // SecurityConfig 파일 생성 후 더이상 /login 파일이 default page로 이동하지 않음
    @GetMapping("/login")
    public String loginForm() {
        return "loginForm";
    }

    @GetMapping("/signup")
    public String signup() {
        return "signup";
    }

    @PostMapping("/signup")
    public String signup(User user) {
        System.out.println("회원가입 진행 : " + user);
        String rawPassword = user.getPassword();
        String encPassword = bCryptPasswordEncoder.encode(rawPassword);
        user.setPassword(encPassword);
        user.setRole("ROLE_USER");
        userRepository.save(user);
        return "redirect:/";
    }
}
