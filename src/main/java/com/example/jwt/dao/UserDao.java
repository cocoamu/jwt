package com.example.jwt.dao;

import com.example.jwt.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * <h1>User Dao 接口定义</h1>
 * */
public interface UserDao extends JpaRepository<User, Long> {

    /**
     * <h2>根据用户名查询 User 对象</h2>
     * select * from t_ecommerce_user where username = ?
     * */
    User findByUsername(String username);

    /**
     * <h2>根据用户名和密码查询实体对象</h2>
     * select * from t_user where username = ? and password = ?
     * */
    User findByUsernameAndPassword(String username, String password);
}
