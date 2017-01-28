# spring-rest-login
Configuration adapter for REST API authorization with Spring security


[![Build Status](https://travis-ci.org/pelenthium/spring-rest-login.svg?branch=master)](https://travis-ci.org/pelenthium/spring-rest-login)

For SPA we can't to use HttpSecurity.formLogin(). We need to support REST API authorization with json.
HttpSecurity.appy(new RestLoginConfigurer<>()) - this line adds to configuration some features :
* RestUsernamePasswordAuthenticationFilter - authorization filter for support json
* RestAuthenticationEntryPoint - send 401 status code for unauthorized requests
* RestAuthenticationSuccessHandler - send information about user (extracting from UserDetails) when authorization is successful

Examples configuration : 
```
    @Configuration
    public static class ApiWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {
        
        @Autowired
        private ObjectMapper mapper;

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.
                    csrf().disable()
                    .antMatcher("/api/v1/super/security/urls")
                    .authorizeRequests()
                    .anyRequest()
                    .hasAnyRole("ROLE_ADMIN")
                    .and()
                    .apply(new RestLoginConfigurer<>(mapper))
                    .loginProcessingUrl("/api/v1/auth")
                    .permitAll();
        }
     }
```
Try to login : 
```
curl -X POST -d '{"username":"admin", "password":"123"}' http://localhost:8080/api/v1/auth

{"expired":false,"credentialsNonExpired":true,"locked":false,"enabled":true,"username":"admin"}
```


### Download
#### Jar 
 You can download [spring-rest-login.jar](https://dl.bintray.com/pelenthium/maven/com/github/cementovoz/spring-rest-login/0.0.1-RELEASE/:spring-rest-login-0.0.1-RELEASE.jar)
#### Gradle 

```
compile 'com.github.cementovoz:spring-rest-login:0.0.1-RELEASE'
```
Don't forget to add to resposiries
```
repositories {
     maven {
         url  "https://dl.bintray.com/pelenthium/maven"
     }
 }
```

#### Maven
```
<dependency>
  <groupId>com.github.cementovoz</groupId>
  <artifactId>spring-rest-login</artifactId>
  <version>0.0.1-RELEASE</version>
  <type>pom</type>
</dependency>
```
Don't forget to add to settings.xml path to bintray repository:
```
<?xml version='1.0' encoding='UTF-8'?>
 <settings xsi:schemaLocation='http://maven.apache.org/SETTINGS/1.0.0 http://maven.apache.org/xsd/settings-1.0.0.xsd' xmlns='http://maven.apache.org/SETTINGS/1.0.0' xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance'>
 <profiles>
 	<profile>
 		<repositories>
 			<repository>
 				<snapshots>
 					<enabled>false</enabled>
 				</snapshots>
 				<id>bintray-pelenthium-maven</id>
 				<name>bintray</name>
 				<url>https://dl.bintray.com/pelenthium/maven</url>
 			</repository>
 		</repositories>
 		<id>bintray</id>
 	</profile>
 </profiles>
 <activeProfiles>
 	<activeProfile>bintray</activeProfile>
 </activeProfiles>
 </settings>
```
