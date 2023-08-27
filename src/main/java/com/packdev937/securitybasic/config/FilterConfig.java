package com.packdev937.securitybasic.config;

import com.packdev937.securitybasic.filter.MyFilter1;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class FilterConfig {
    @Bean
    public FilterRegistrationBean<MyFilter1> filter1(){
        FilterRegistrationBean<MyFilter1> bean = new FilterRegistrationBean<>(new MyFilter1());
        // 모든 요청에서 다
        bean.addUrlPatterns("/*");
        // 우선 순위를 설정 (0이 가장 높음)
        bean.setOrder(0);
        return bean;
    }
}
