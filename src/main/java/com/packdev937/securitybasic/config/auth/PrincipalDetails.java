package com.packdev937.securitybasic.config.auth;

import com.packdev937.securitybasic.entity.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;
import java.util.Optional;

// Authentication 객체에 저장할 수 있는 유일한 타입
public class PrincipalDetails implements UserDetails, OAuth2User {
    private static final long serialVersionUID = 1L;
    private Optional<User> user;
    private Map<String, Object> attributes;

    // 일반 시큐리티 로그인 시 사용
    public PrincipalDetails(Optional<User> user) {
        this.user = user;
    }

    // Oauth 2.0 로그인 시 사용
    public PrincipalDetails(Optional<User> user, Map<String, Object> attributes) {
        this.user = user;
        this.attributes = attributes;
    }

    public Optional<User> getUser() {
        return user;
    }

    // Optional<User> 하게 되면 user.get().get() 형태로 값을 불러와야되는가?
    @Override
    public String getName() {
        return user.get().getId() + ""; // 뒤에 붙은 ""가 무엇을 의미하는가?
    } // 잘 사용되지 않음

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    // User의 권한을 리턴하는 곳
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> collect = new ArrayList<>(); // 여기서 GrantedAuthority가 의미하는게 무엇인가?
        collect.add(() -> {
            return user.get().getRole();
        });
        return collect;
    }

    @Override
    public String getPassword() {
        return user.get().getPassword();
    }

    @Override
    public String getUsername() {
        return null;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return false;
    }
}
