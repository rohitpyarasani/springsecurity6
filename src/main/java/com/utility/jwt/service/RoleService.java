package com.utility.jwt.service;

import com.utility.jwt.dao.RoleDao;
import com.utility.jwt.entity.Role;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class RoleService {

    @Autowired
    private RoleDao roleDao;
    public Role createNewRole(Role role){
        return roleDao.save(role);
    }
}
