package com.kll.oauth.component;

import com.kll.oauth.domain.SecurityUser;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

/**
 *
 *          JWT内容增强
 *
 *          AuthorizationServerConfigurerAdapter实现的配置类中的
 *          configure(AuthorizationServerEndpointsConfigurer endpoints)添加相应的增强
 */
@Component
public class JwtTokenEnhancer implements TokenEnhancer {
    @Override
    public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
        //从鉴权信息中获取userDetail,转换成自定义的UserDetail
        SecurityUser securityUser = (SecurityUser) authentication.getPrincipal();
        Map<String, Object> info = new HashMap<>();
        info.put("id", securityUser.getId());
        //将用户信息ID设置到JWT中去
        //此方法是OAuthAccessToken默认实现的类中实现的方法，在Oauth2AccessToken中没有
        ((DefaultOAuth2AccessToken) accessToken).setAdditionalInformation(info);
        return accessToken;
    }
}
