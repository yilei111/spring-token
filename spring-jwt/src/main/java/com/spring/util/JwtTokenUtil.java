package com.spring.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.PropertySource;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * JwtToken生成的工具类
 *
 * @author yilei
 * @className JwtTokenUtil
 * @date 2021/3/1 20:33
 **/
@Component
@PropertySource("classpath:conf/jwt.properties")
public class JwtTokenUtil implements InitializingBean {

    private static final Logger LOGGER = LoggerFactory.getLogger(JwtTokenUtil.class);

    private static final String CLAIM_KEY_CLIENT_ID = "client";
    private static final String CLAIM_KEY_CREATED = "created";

    @Value("${jwt.secret}")
    private String secret;
    @Value("${jwt.expire}")
    private Long expire;

    private static String JWT_SECRET;
    private static Long JWT_EXPIRE;

    @Override
    public void afterPropertiesSet() {
        JWT_SECRET = secret;
        JWT_EXPIRE = expire;
    }

    /**
     * 生成token
     *
     * @param clientId
     * @return java.lang.String
     * @author yilei
     * @date 2021-03-01 20:04
     */
    public static String generateToken(String clientId) {
        Map<String, Object> claims = new HashMap<>(3);
        claims.put(CLAIM_KEY_CLIENT_ID, clientId);
        claims.put(CLAIM_KEY_CREATED, new Date());
        return generateToken(claims);
    }

    /**
     * 根据claims生成token
     *
     * @param claims
     * @return java.lang.String
     * @author yilei
     * @date 2021-03-01 20:04
     */
    public static String generateToken(Map<String, Object> claims) {
        return Jwts.builder()
                .setClaims(claims)
                .setExpiration(new Date(System.currentTimeMillis() + JWT_EXPIRE * 1000))
                .signWith(SignatureAlgorithm.HS512, JWT_SECRET)
                .compact();
    }

    /**
     * 根据token获取claims
     *
     * @param token
     * @return io.jsonwebtoken.Claims
     * @author yilei
     * @date 2021-03-01 20:04
     */
    public static Claims getClaimsFromToken(String token) {
        Claims claims = null;
        try {
            claims = Jwts.parser()
                    .setSigningKey(JWT_SECRET)
                    .parseClaimsJws(token)
                    .getBody();
        } catch (Exception e) {
            LOGGER.info("JWT格式验证失败:{}", token);
        }
        return claims;
    }

    /**
     * 验证token是否合法
     * 1、client_id是否匹配
     * 2、expire是否过期
     *
     * @param token
     * @param clientId
     * @return boolean
     * @author yilei
     * @date 2021-03-01 20:04
     */
    public static boolean validateToken(String token, String clientId) {
        Claims claims = getClaimsFromToken(token);
        if (null == claims) {
            return false;
        }
        Object cId = claims.get(CLAIM_KEY_CLIENT_ID);
        if (null == cId) {
            return false;
        }
        return StringUtils.equals(clientId, cId.toString()) && !isTokenExpired(token);
    }

    /**
     * 判断token是否已经失效
     *
     * @param token
     * @return boolean
     * @author yilei
     * @date 2021-03-01 20:04
     */
    public static boolean isTokenExpired(String token) {
        Claims claims = getClaimsFromToken(token);
        Date expiredDate = claims.getExpiration();
        return expiredDate.before(new Date());
    }

    public static void main(String[] args) {
        String token = JwtTokenUtil.generateToken("123456");
        System.out.println(token);
        System.out.println("============");
        String aa = "eyJhbGciOiJIUzUxMiJ9.eyJleHAiOjE2MTQ2MDg3NjgsImNsaWVudCI6IjEyMzQ1NiIsImNyZWF0ZWQiOjE2MTQ2MDg3MDg2MDV9.DyVpgKZ_2_8fP1gQdNYzdH5pI5JM7diw1ivXTHGtl1ayH6KQn3K3pRxGn1xrQRVzJyz6flLooY2_611XE8RNZA";
        Claims claimsFromToken = JwtTokenUtil.getClaimsFromToken(aa);
        System.out.println(claimsFromToken);
    }
}
