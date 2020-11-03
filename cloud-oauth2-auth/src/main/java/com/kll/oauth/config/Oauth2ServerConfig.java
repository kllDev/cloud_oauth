package com.kll.oauth.config;

import com.kll.oauth.component.JwtTokenEnhancer;
import com.kll.oauth.service.UserServiceImpl;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.redis.RedisTokenStore;
import org.springframework.security.rsa.crypto.KeyStoreKeyFactory;

import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;

/**
 * 认证服务器配置
 * Created by macro on 2020/6/19.
 */
@AllArgsConstructor
@Configuration
@EnableAuthorizationServer
public class Oauth2ServerConfig extends AuthorizationServerConfigurerAdapter {
    //密码编码器
    private final PasswordEncoder passwordEncoder;
    //userDetails实现类，用于保存用户信息，同时实现loadUserByUsername()，来返回用户信息
    private final UserServiceImpl userDetailsService;
    //鉴权管理器
    private final AuthenticationManager authenticationManager;
    //JWTtoken增强
    private final JwtTokenEnhancer jwtTokenEnhancer;
    //redis连接工厂
    @Autowired
    private RedisConnectionFactory connectionFactory;

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory()
                .withClient("client-app")
                .secret(passwordEncoder.encode("123456"))
                .scopes("all")
                .authorizedGrantTypes("password", "refresh_token")
//                .redirectUris("http://localhost:8882/login", "http://localhost:8883/login")    // 认证成功重定向URL
                .accessTokenValiditySeconds(3600)
                .refreshTokenValiditySeconds(86400);

    }

    //告诉spring security token的生成方式
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        TokenEnhancerChain enhancerChain = new TokenEnhancerChain();
        List<TokenEnhancer> delegates = new ArrayList<>();
        delegates.add(jwtTokenEnhancer);
        delegates.add(accessTokenConverter());
        enhancerChain.setTokenEnhancers(delegates); //配置JWT的内容增强器
        endpoints.authenticationManager(authenticationManager)
                .userDetailsService(userDetailsService) //配置加载用户信息的服务
                .accessTokenConverter(accessTokenConverter())
                .tokenEnhancer(enhancerChain)
//                //配置token存储的服务与位置
//                .tokenServices(tokenService())
                .tokenStore(tokenStore());
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        security.allowFormAuthenticationForClients();
    }

    @Bean
    public TokenStore tokenStore() {
        //使用redis存储token
        RedisTokenStore redisTokenStore = new RedisTokenStore(connectionFactory);
        //设置redis token存储中的前缀
        redisTokenStore.setPrefix("auth-token:");
        return redisTokenStore;
    }
//
//    @Bean
//    public DefaultTokenServices tokenService() {
//        DefaultTokenServices tokenServices = new DefaultTokenServices();
//        //配置token存储
//        tokenServices.setTokenStore(tokenStore());
//        //开启支持refresh_token，此处如果之前没有配置，启动服务后再配置重启服务，可能会导致不返回token的问题，解决方式：清除redis对应token存储
//        tokenServices.setSupportRefreshToken(true);
//        //复用refresh_token
//        tokenServices.setReuseRefreshToken(true);
//        //token有效期，设置12小时
//        tokenServices.setAccessTokenValiditySeconds(12 * 60 * 60);
//        //refresh_token有效期，设置一周
//        tokenServices.setRefreshTokenValiditySeconds(7 * 24 * 60 * 60);
//        return tokenServices;
//    }


//
//    @Override
//    public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
//        oauthServer
//                .realm("oauth2-resources")
//                //url:/oauth/token_key,exposes public key for token verification if using JWT tokens
//                .tokenKeyAccess("permitAll()")
//                //url:/oauth/check_token allow check token
//                .checkTokenAccess("isAuthenticated()")
//                .allowFormAuthenticationForClients();
//    }
//
//    @Override
//    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
//        endpoints.authenticationManager(authenticationManager);
//    }

//    @Override
//    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
//        clients.inMemory()
//                .withClient("client")
//                .secret(passwordEncoder.encode("secret"))
////                .redirectUris("http://example.com")
//                // 客户端认证方式兼容了5种模式
//                .authorizedGrantTypes("authorization_code", "client_credentials", "refresh_token",
//                        "password", "implicit")
//                .scopes("all")
//                .resourceIds("oauth2-resource")
//                .accessTokenValiditySeconds(1200)
//                .refreshTokenValiditySeconds(50000);
//    }


    @Bean
    public JwtAccessTokenConverter accessTokenConverter() {
        JwtAccessTokenConverter jwtAccessTokenConverter = new JwtAccessTokenConverter();
        jwtAccessTokenConverter.setSigningKey("123456");
//        设置jwt为公钥私钥形式的非对称加密形式
//        jwtAccessTokenConverter.setKeyPair(keyPair());
        return jwtAccessTokenConverter;
    }

    //非对称加密获取公钥的方法
    @Bean
    public KeyPair keyPair() {
        //从classpath下的证书中获取秘钥对
        KeyStoreKeyFactory keyStoreKeyFactory = new KeyStoreKeyFactory(new ClassPathResource("jwt.jks"), "112358".toCharArray());
        return keyStoreKeyFactory.getKeyPair("jwt", "112358".toCharArray());
    }

}
