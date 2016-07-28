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
package com.github.cementovoz.spring.rest.login;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;


public class RestAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {


    private final ObjectMapper mapper;

    public RestAuthenticationSuccessHandler(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

        clearAuthenticationAttributes(request);
        Object principal = authentication.getPrincipal();
        if (principal instanceof UserDetails) {
            UserDetails details = (UserDetails) principal;
            mapper.writeValue(response.getOutputStream(), new HashMap<String, Object>() {{
                put("username", details.getUsername());
                put("enabled", details.isEnabled());
                put("credentialsNonExpired", details.isCredentialsNonExpired());
                put("expired", !details.isAccountNonExpired());
                put("locked", !details.isAccountNonLocked());
            }});
            response.setHeader("Content-type", "application/json");
            response.setContentType("application/json");
        }
    }
}