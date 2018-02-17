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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.bind.annotation.RequestMethod;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class RestUsernamePasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private ObjectMapper mapper;

    private String usernameParameter = "username";
    private String passwordParameter = "password";

    @Autowired
    public RestUsernamePasswordAuthenticationFilter(ObjectMapper mapper) {
        this.mapper = mapper;
        setFilterProcessesUrl("/api/v1/login");
        setAuthenticationSuccessHandler(new RestAuthenticationSuccessHandler(mapper));
        setAuthenticationFailureHandler(new RestAuthenticationFailureHandler());
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        if (!RequestMethod.POST.name().equals(request.getMethod())) {
            throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
        }

        try {
            UsernameAndPasswordModel model = new UsernameAndPasswordModel(mapper, request);
            UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(
                    model.getUsername(), model.getPassword());

            authRequest.setDetails(authenticationDetailsSource.buildDetails(request));

            return this.getAuthenticationManager().authenticate(authRequest);
        } catch (Exception e) {
            throw new AuthenticationServiceException("Authentication is failed ", e);
        }

    }

    public class UsernameAndPasswordModel {
        private String username;
        private String password;

        public UsernameAndPasswordModel(ObjectMapper mapper, HttpServletRequest request) throws IOException {
            JsonNode jsonNode = mapper.readTree(request.getReader());
            username = jsonNode.get(usernameParameter).asText();
            password = jsonNode.get(passwordParameter).asText();
        }

        public String getUsername() {
            return username == null ? "" : username;
        }

        public String getPassword() {
            return password == null ? "" : password;
        }
    }
}
