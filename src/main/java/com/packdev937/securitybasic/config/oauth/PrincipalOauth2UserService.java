package com.packdev937.securitybasic.config.oauth;

import com.packdev937.securitybasic.config.auth.PrincipalDetails;
import com.packdev937.securitybasic.entity.User;
import com.packdev937.securitybasic.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@Slf4j
@RequiredArgsConstructor
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final UserRepository userRepository;
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        System.out.println("getClientRegistration:" + userRequest.getClientRegistration());
        System.out.println("getAccessToken: " + userRequest.getAccessToken());
        System.out.println("getAttributes: " + super.loadUser(userRequest).getAttributes());

        OAuth2User oAuth2User = super.loadUser(userRequest);
        // 강제 회원 가입 (필드 값들을 다 채워준다)
        String provider = userRequest.getClientRegistration().getClientId();
        String providerId = oAuth2User.getAttribute("sub"); // 여기서의 getAttribute는 principalDetails에서 구현한 getAttribute()와 다른건가
        // Oauth 로그인에는 크게 의미 없는 username과 password
        String username = provider+"_"+providerId;
        String password = bCryptPasswordEncoder.encode("packdev937");
        String email = oAuth2User.getAttribute("email");
        String role = "ROLE_USER";

        // 회원 가입이 되어 있는지 확인해야 한다
        Optional<User> userEntity = userRepository.findByUsername(username);
        if(!userEntity.isPresent()){
            userEntity = Optional.ofNullable(User.builder()
                    .username(username)
                    .password(password)
                    .email(email)
                    .role(role)
                    .provider(provider)
                    .providerId(providerId)
                    .build());

            userRepository.save(userEntity);
        }
        return new PrincipalDetails(userEntity, oAuth2User.getAttributes());
    }
}
