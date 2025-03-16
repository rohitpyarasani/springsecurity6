package com.utility.jwt.service;

import com.utility.jwt.dao.UserDao;
import com.utility.jwt.entity.JwtRequest;
import com.utility.jwt.entity.JwtResponse;
import com.utility.jwt.entity.User;
import com.utility.jwt.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

@Service
public class JwtService implements UserDetailsService {

    @Autowired
    private UserDao userDao;
    @Autowired
    private JwtUtil jwtUtil;
    @Autowired
    private AuthenticationManager authenticationManager;

    public JwtService(UserDao userDao, JwtUtil jwtUtil,@Lazy AuthenticationManager authenticationManager) {
        this.userDao = userDao;
        this.jwtUtil = jwtUtil;
        this.authenticationManager = authenticationManager;
    }

    public JwtResponse createJwtToken(JwtRequest request) throws Exception {
        String userName = request.getUserName();
        String userPassword = request.getUserPassword();
        authenticate(userName,userPassword);
        final UserDetails userDetails = loadUserByUsername(userName);
        String newGeneratedToken = jwtUtil.generateToken(userDetails);
        User user = userDao.findById(userName).get();

        return new JwtResponse(user,newGeneratedToken);
    }
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userDao.findById(username).get();
        if(user !=null){
            return new org.springframework.security.core.userdetails.User(
                    user.getUserName(),user.getUserPassword(),getAuthorities(user)
            );
        }else{
            throw new UsernameNotFoundException("UserName is not valid");
        }
    }

    private Set getAuthorities(User user){
        Set authorities = new HashSet();
        user.getRole().forEach(role -> {
            authorities.add(new SimpleGrantedAuthority("ROLE_"+role.getRoleName()));
        });

        return authorities;
    }

    private void authenticate(String userName, String userPassword) throws Exception{
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(userName,userPassword));
        }catch (DisabledException ex){
            throw new Exception("User is disabled");
        }catch (BadCredentialsException ex){
            throw new Exception("Bad credentials from user");
        }

    }
}
