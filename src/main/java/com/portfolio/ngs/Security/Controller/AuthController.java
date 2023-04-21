/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.portfolio.ngs.Security.Controller;

import com.portfolio.ngs.Security.Dto.JwtDto;
import com.portfolio.ngs.Security.Dto.LoginUsuario;
import com.portfolio.ngs.Security.Dto.NuevoUsuario;
import com.portfolio.ngs.Security.Entity.Rol;
import com.portfolio.ngs.Security.Entity.Usuario;
import com.portfolio.ngs.Security.Enums.RolNombre;
import com.portfolio.ngs.Security.Service.RolService;
import com.portfolio.ngs.Security.Service.UsuarioService;
import com.portfolio.ngs.Security.jwt.JwtEntryPoint;
import com.portfolio.ngs.Security.jwt.JwtProvider;
import java.util.HashSet;
import java.util.Set;
import javax.validation.Valid;
import static org.apache.tomcat.jni.User.username;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
@CrossOrigin(origins =  {"https://portfoliowebap.web.app" , "http://localhost:4200"})
public class AuthController {
    private final static Logger logger = LoggerFactory.getLogger(AuthController.class);

    @Autowired
    PasswordEncoder passwordEncoder;
    @Autowired
    AuthenticationManager authenticationManager;
    @Autowired
    UsuarioService usuarioService;
    @Autowired
    RolService rolService;
    @Autowired
    JwtProvider jwtProvider;
    
    @PostMapping("/nuevo")
    public ResponseEntity<?> nuevo(@Valid @RequestBody NuevoUsuario nuevoUsuario, BindingResult bindingResult){
        if(bindingResult.hasErrors())
            return new ResponseEntity(new Mensaje("Campos mal puestos o email invalido"),HttpStatus.BAD_REQUEST);
        
        if(usuarioService.existsByNombreUsuario(nuevoUsuario.getNombreUsuario()))
            return new ResponseEntity(new Mensaje("Ese nombre de usuario ya existe"), HttpStatus.BAD_REQUEST);
        
        if(usuarioService.existsByEmail(nuevoUsuario.getEmail()))
            return new ResponseEntity(new Mensaje("Ese email ya existe"), HttpStatus.BAD_REQUEST);
        
        Usuario usuario = new Usuario(nuevoUsuario.getNombre(), nuevoUsuario.getNombreUsuario(),
            nuevoUsuario.getEmail(), passwordEncoder.encode(nuevoUsuario.getPassword()));
        
        Set<Rol> roles = new HashSet<>();
        roles.add(rolService.getByRolNombre(RolNombre.ROLE_USER).get());
        
        if(nuevoUsuario.getRoles().contains("admin"))
            roles.add(rolService.getByRolNombre(RolNombre.ROLE_ADMIN).get());
        usuario.setRoles(roles);
        usuarioService.save(usuario);
        
        return new ResponseEntity(new Mensaje("Usuario guardado"),HttpStatus.CREATED);
    }
    
    @PostMapping("/login")
    public ResponseEntity<JwtDto> login(@Valid @RequestBody LoginUsuario loginUsuario, BindingResult bindingResult) throws Exception{
        logger.info("Estoy en el login 1");
        if(bindingResult.hasErrors())
            return new ResponseEntity(new Mensaje("Campos mal puestos"), HttpStatus.BAD_REQUEST);
        logger.info("USUARIO: " + loginUsuario.getNombreUsuario());
        logger.info("PASS: " + loginUsuario.getPassword());
        
       Authentication authentication = null;
    try {
    authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
        loginUsuario.getNombreUsuario(), loginUsuario.getPassword()));
	} catch (DisabledException e) {
			logger.info("catch1");
     throw new Exception("USER_DISABLED", e);
		} catch (BadCredentialsException e) {
			logger.info("catch2");
     throw new Exception("INVALID_CREDENTIALS", e);
		}
       
        
        logger.info("Estoy en el login 2");
        SecurityContextHolder.getContext().setAuthentication(authentication);
        logger.info("Estoy en el login 3");
        String jwt = jwtProvider.generateToken(authentication);
        logger.info("Estoy en el login 4");
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        
        JwtDto jwtDto = new JwtDto(jwt, userDetails.getUsername(), userDetails.getAuthorities());
        logger.info("Estoy en el login 5");
        return new ResponseEntity(jwtDto, HttpStatus.OK);
    }
    
    
}