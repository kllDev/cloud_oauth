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
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.redis.RedisTokenStore;
import org.springframework.security.rsa.crypto.KeyStoreKeyFactory;

import javax.sql.DataSource;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;

/**
 * Authorization Server - 授权服务器
 */
@AllArgsConstructor
@Configuration
@EnableAuthorizationServer
public class Oauth2ServerConfig extends AuthorizationServerConfigurerAdapter {



    private final UserServiceImpl userDetailsService;
    //鉴权管理器
    private final AuthenticationManager authenticationManager;
    private final JwtTokenEnhancer jwtTokenEnhancer;

    //JDBC获取客户端信息的服务
    @Bean
    public JdbcClientDetailsService jdbcClientDetailsService() {
        return new JdbcClientDetailsService(dataSource);
    }

    @Autowired
    private DataSource dataSource;

    @Autowired
    private RedisConnectionFactory connectionFactory;

    @Bean
    public TokenStore tokenStore() {
        //使用redis存储token
        RedisTokenStore redisTokenStore = new RedisTokenStore(connectionFactory);
        //设置redis token存储中的前缀
        redisTokenStore.setPrefix("auth-token:");
        return redisTokenStore;
    }

    //配置客户端信息
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.withClientDetails(jdbcClientDetailsService());  //设置客户端的配置从数据库中读取，存储在oauth_client_details表
        //内存中配置客户端信息
//        clients.inMemory()
//                .withClient("client-app")
//                .secret(passwordEncoder.encode("123456"))
//                .scopes("all")
//                .authorizedGrantTypes("password", "refresh_token")
////                .redirectUris("http://localhost:8882/login", "http://localhost:8883/login")    // 认证成功重定向URL
//                .accessTokenValiditySeconds(3600)
//                .refreshTokenValiditySeconds(86400);

    }

    //告诉spring security token的生成方式
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints.authenticationManager(authenticationManager)
                .userDetailsService(userDetailsService)
                .tokenStore(tokenStore());
//        TokenEnhancerChain enhancerChain = new TokenEnhancerChain();
//        List<TokenEnhancer> delegates = new ArrayList<>();
//        delegates.add(jwtTokenEnhancer);
//        delegates.add(accessTokenConverter());
//        enhancerChain.setTokenEnhancers(delegates); //配置JWT的内容增强器
//        endpoints.authenticationManager(authenticationManager)
//                .userDetailsService(userDetailsService) //配置加载用户信息的服务
//                .accessTokenConverter(accessTokenConverter())
//                .tokenEnhancer(enhancerChain)
////                //配置token存储的服务与位置
////                .tokenServices(tokenService())
//                .tokenStore(tokenStore());
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        security.tokenKeyAccess("permitAll()");  // 获取 token 的策略
        security.checkTokenAccess("isAuthenticated()");
//        security.allowFormAuthenticationForClients();
    }



    @Bean
    public JwtAccessTokenConverter accessTokenConverter() {
        JwtAccessTokenConverter jwtAccessTokenConverter = new JwtAccessTokenConverter();
//        设置jwt为公钥私钥形式的非对称加密形式
        jwtAccessTokenConverter.setKeyPair(keyPair());
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
