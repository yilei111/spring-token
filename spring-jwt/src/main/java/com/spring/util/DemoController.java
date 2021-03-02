package com.spring.util;

import cn.hutool.core.date.DateUnit;
import cn.hutool.core.date.DateUtil;
import com.alibaba.fastjson.JSON;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * 测试
 *
 * @author yilei
 * @className DemoController
 * @date 2021/3/1 20:33
 **/
@Controller
public class DemoController {

    /**
     * 获取access_token
     *
     * @param clientId     客户端ID
     * @param clientSecret 客户端secret
     * @return java.lang.String
     * @author yilei
     * @date 2021-03-01 21:32
     */
    @RequestMapping(value = "tokens")
    @ResponseBody
    public String tokens(String clientId, String clientSecret) {
        Map<String, Object> map = new HashMap<>(16);
        // 验证客户端ID，密钥是否匹配
        if (StringUtils.equals("ddddd", clientId) && StringUtils.equals("sssss", clientSecret)) {
            // 生成access_token
            String token = JwtTokenUtil.generateToken(clientId);
            map.put("code", 1);
            map.put("access_token", token);
            Date expiration = JwtTokenUtil.getClaimsFromToken(token).getExpiration();
            map.put("expires_in", DateUtil.between(expiration, new Date(), DateUnit.MS));
        } else {
            map.put("code", -1);
            map.put("msg", "授权信息不正确！");
        }
        return JSON.toJSONString(map);
    }

    /**
     * 校验token
     *
     * @param token
     * @param clientId 客户端ID
     * @return java.lang.String
     * @author yilei
     * @date 2021-03-01 21:33
     */
    @RequestMapping(value = "tokens/check")
    @ResponseBody
    public String tokensCheck(@RequestHeader String token, @RequestParam String clientId) {
        Map<String, Object> map = new HashMap<>(16);
        boolean flag = JwtTokenUtil.validateToken(token, clientId);
        if (flag) {
            map.put("code", 1);
            map.put("client_id", clientId);
            Date expiration = JwtTokenUtil.getClaimsFromToken(token).getExpiration();
            map.put("expires_in", DateUtil.between(expiration, new Date(), DateUnit.MS));
        } else {
            map.put("code", -1);
            map.put("msg", "非法token或token已过期！");
        }
        return JSON.toJSONString(map);
    }
}
