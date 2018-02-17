/**
 * The MIT License (MIT)
 *
 * Copyright (c) 2016 Serge L
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package com.github.pelenthium.spring.rest.login;


import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.web.accept.ContentNegotiationStrategy;
import org.springframework.web.accept.HeaderContentNegotiationStrategy;

import java.util.Collections;

public class RestLoginConfigurer<B extends HttpSecurityBuilder<B>, T extends RestLoginConfigurer>
        extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, B> {

    private boolean permitAll;
    private AbstractAuthenticationProcessingFilter filter;
    private String loginProcessingUrl;
    private AuthenticationSuccessHandler successHandler;
    private AuthenticationFailureHandler failureHandler = new RestAuthenticationFailureHandler();

    public RestLoginConfigurer(ObjectMapper mapper) {
        this(new RestUsernamePasswordAuthenticationFilter(mapper), mapper);
    }

    public RestLoginConfigurer(RestUsernamePasswordAuthenticationFilter filter, ObjectMapper mapper) {
        this.filter = filter;
        loginProcessingUrl("/api/login");
        this.successHandler = new RestAuthenticationSuccessHandler(mapper);
    }

    @Override
    public void init(B http) throws Exception {
        AuthenticationEntryPoint authenticationEntryPoint = new RestAuthenticationEntryPoint();

        ExceptionHandlingConfigurer<B> exceptionHandling = http.getConfigurer(ExceptionHandlingConfigurer.class);
        if (exceptionHandling == null) {
            return;
        }
        ContentNegotiationStrategy contentNegotiationStrategy = http
                .getSharedObject(ContentNegotiationStrategy.class);
        if (contentNegotiationStrategy == null) {
            contentNegotiationStrategy = new HeaderContentNegotiationStrategy();
        }
        MediaTypeRequestMatcher preferredMatcher = new MediaTypeRequestMatcher(
                contentNegotiationStrategy, MediaType.APPLICATION_JSON);
        preferredMatcher.setIgnoredMediaTypes(Collections.singleton(MediaType.ALL));
        exceptionHandling.defaultAuthenticationEntryPointFor(
                postProcess(authenticationEntryPoint), preferredMatcher);
    }

    @Override
    public void configure(B http) throws Exception {
        if (permitAll) {
            ExpressionUrlAuthorizationConfigurer<?> configurer = http
                    .getConfigurer(ExpressionUrlAuthorizationConfigurer.class);
            configurer.getRegistry().requestMatchers(new AntPathRequestMatcher(loginProcessingUrl)).permitAll();
        }
        filter.setAuthenticationManager(http.getSharedObject(AuthenticationManager.class));

        filter.setAuthenticationManager(http
                .getSharedObject(AuthenticationManager.class));
        filter.setAuthenticationSuccessHandler(successHandler);
        filter.setAuthenticationFailureHandler(failureHandler);
        SessionAuthenticationStrategy sessionAuthenticationStrategy = http
                .getSharedObject(SessionAuthenticationStrategy.class);
        if (sessionAuthenticationStrategy != null) {
            filter.setSessionAuthenticationStrategy(sessionAuthenticationStrategy);
        }

        http.addFilter(filter);
    }


    public T loginProcessingUrl(String loginProcessingUrl) {
        this.loginProcessingUrl = loginProcessingUrl;
        filter.setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher(loginProcessingUrl, "POST"));
        return getSelf();
    }

    public T permitAll() {
        return permitAll(true);
    }

    public T permitAll(boolean permitAll) {
        this.permitAll = permitAll;
        return getSelf();
    }

    public T successHandler(AuthenticationSuccessHandler successHandler) {
        this.successHandler = successHandler;
        return getSelf();
    }

    public T failureHandler(AuthenticationFailureHandler failureHandler) {
        this.failureHandler = failureHandler;
        return getSelf();
    }

    @SuppressWarnings("unchecked")
    private T getSelf() {
        return (T) this;
    }
}
