package com.example.jwt.service.impl;

import com.alibaba.fastjson.JSON;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.example.jwt.constant.CommonConstant;
import com.example.jwt.dao.UserDao;
import com.example.jwt.entity.User;
import com.example.jwt.service.IJWTService;
import com.example.jwt.vo.LoginUserInfo;
import com.sun.org.apache.xml.internal.security.algorithms.SignatureAlgorithm;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import sun.misc.BASE64Decoder;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.LocalDate;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.UUID;

import static com.example.jwt.constant.CommonConstant.SECRET;

/**
 * <h1>JWT 相关服务接口实现</h1>
 * */
@Slf4j
@Service
@Transactional(rollbackFor = Exception.class)
public class JWTServiceImpl implements IJWTService {

    /** 默认的 Token 超时时间, 一天 */
    private static final Integer DEFAULT_EXPIRE_DAY = 1;

    private final UserDao userDao;

    public JWTServiceImpl(UserDao userDao) {
        this.userDao = userDao;
    }

    @Override
    public String generateToken(String username, String password) throws Exception {

        return generateToken(username, password, 0);
    }

    @Override
    public String generateToken(String username, String password, int expire)
            throws Exception {
        Algorithm algorithm = Algorithm.HMAC256(SECRET);

        // 首先需要验证用户是否能够通过授权校验, 即输入的用户名和密码能否匹配数据表记录
        User ecommerceUser = userDao.findByUsernameAndPassword(
                username, password
        );
        if (null == ecommerceUser) {
            log.error("can not find user: [{}], [{}]", username, password);
            return null;
        }

        // Token 中塞入对象, 即 JWT 中存储的信息, 后端拿到这些信息就可以知道是哪个用户在操作
        LoginUserInfo loginUserInfo = new LoginUserInfo(
                ecommerceUser.getId(), ecommerceUser.getUsername()
        );

        if (expire <= 0) {
            expire = DEFAULT_EXPIRE_DAY;
        }

        // 计算超时时间
        ZonedDateTime zdt = LocalDate.now().plus(expire, ChronoUnit.DAYS)
                .atStartOfDay(ZoneId.systemDefault());
        Date expireDate = Date.from(zdt.toInstant());

        return JWT.create()
                // jwt payload --> KV
                .withClaim(CommonConstant.JWT_USER_INFO_KEY, JSON.toJSONString(loginUserInfo))
                // jwt id
                .withJWTId(UUID.randomUUID().toString())
                // jwt 过期时间
                .withExpiresAt(expireDate)
                // jwt 签名 --> 加密
                .sign(algorithm);
    }

    @Override
    public String registerUserAndGenerateToken(String username, String password)
            throws Exception {

        // 先去校验用户名是否存在, 如果存在, 不能重复注册
        User oldUser = userDao.findByUsername(username);
        if (null != oldUser) {
            log.error("username is registered: [{}]", oldUser.getUsername());
            return null;
        }

        User ecommerceUser = new User();
        ecommerceUser.setUsername(username);
        ecommerceUser.setPassword(password);   // MD5 编码以后
        ecommerceUser.setExtraInfo("{}");

        // 注册一个新用户, 写一条记录到数据表中
        ecommerceUser = userDao.save(ecommerceUser);
        log.info("register user success: [{}], [{}]", ecommerceUser.getUsername(),
                ecommerceUser.getId());

        // 生成 token 并返回
        return generateToken(ecommerceUser.getUsername(), ecommerceUser.getPassword());
    }
}
