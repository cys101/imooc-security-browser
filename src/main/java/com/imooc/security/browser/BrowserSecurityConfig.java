package com.imooc.security.browser;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenBasedRememberMeServices;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.social.security.SpringSocialConfigurer;

import com.imooc.security.browser.authentication.ImoocAuthenticationFailureHandler;
import com.imooc.security.browser.authentication.ImoocAuthenticationSuccessHandler;
import com.imooc.security.core.authentication.mobile.AbstractChannelSecurityConfig;
import com.imooc.security.core.constants.SecurityConstants;
import com.imooc.security.core.properties.SecurityProperties;
import com.imooc.security.core.validate.code.SmsCodeAuthenticationSecutiryConfig;
import com.imooc.security.core.validate.code.ValidateCodeFilter;
import com.imooc.security.core.validate.code.ValidateCodeSecurityConfig;
import com.imooc.security.core.validate.code.sms.SmsCodeFilter;

@Configuration
public class BrowserSecurityConfig extends AbstractChannelSecurityConfig {
	@Autowired
	private SecurityProperties securityProperties;
	
	@Autowired
	private DataSource dataSource;
	
	@Autowired
	private UserDetailsService userDetailsService;
	
	@Autowired
	private SmsCodeAuthenticationSecutiryConfig smsCodeAuthenticationSecutiryConfig;
	
	@Autowired
	private ValidateCodeSecurityConfig validateCodeSecurityConfig;
	
	@Autowired
	private AbstractChannelSecurityConfig abstractChannelSecurityConfig;
	
	@Autowired
	private SpringSocialConfigurer imoocSocialSecurityConfig;
	
	@Bean
	public PasswordEncoder getPasswordEncoder(){
		return new BCryptPasswordEncoder();
	}
	
	@Bean
	public PersistentTokenRepository persistentTokenRepository(){
		JdbcTokenRepositoryImpl tokenRepository=new JdbcTokenRepositoryImpl();
		tokenRepository.setDataSource(dataSource);
//		tokenRepository.setCreateTableOnStartup(true);
		return tokenRepository;
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		/*ValidateCodeFilter validateCodeFilter = new ValidateCodeFilter();
		validateCodeFilter.setAuthenticationFailureHandler(imoocAuthenticationFailureHandler);
		validateCodeFilter.setSecurityProperties(securityProperties);
		validateCodeFilter.afterPropertiesSet();
		
		SmsCodeFilter smsCodeFilter = new SmsCodeFilter();
		smsCodeFilter.setAuthenticationFailureHandler(imoocAuthenticationFailureHandler);
		smsCodeFilter.setSecurityProperties(securityProperties);
		smsCodeFilter.afterPropertiesSet();*/
		applyPasswordAuthenticationConfig(http);
		http.apply(validateCodeSecurityConfig)
		    .and()
		    .apply(smsCodeAuthenticationSecutiryConfig).
		    and()
		    .apply(imoocSocialSecurityConfig)
		    .and()
		    .rememberMe()
		      .tokenRepository(persistentTokenRepository())
		      .tokenValiditySeconds(securityProperties.getBrowser().getRememberMeSeconds())
		      .userDetailsService(userDetailsService)
		    .and()
		    .authorizeRequests()
		    .antMatchers(SecurityConstants.DEFAULT_UNAUTHENTICATION_URL,
		    		     SecurityConstants.DEFAULT_VALIDATE_CODE_URL_PREFIX+"/*",
		    		     securityProperties.getBrowser().getLoginPage(),
		    		     securityProperties.getBrowser().getSignUpUrl(),"/user/register")
		    .permitAll()
		    .anyRequest()
		    .authenticated()
		    .and()
		    .csrf().disable();
		    
	}

}
