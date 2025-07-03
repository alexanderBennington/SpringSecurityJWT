package alexander.SpringSecurityJWT;

import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

import alexander.SpringSecurityJWT.models.ERole;
import alexander.SpringSecurityJWT.models.RoleEntity;
import alexander.SpringSecurityJWT.models.UserEntity;
import alexander.SpringSecurityJWT.repositories.UserRepository;

@SpringBootApplication
public class SpringSecurityJwtApplication {

	@Autowired
	PasswordEncoder passwordEncoder;

	@Autowired
	UserRepository userRepository;

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityJwtApplication.class, args);
	}

	@Bean
	CommandLineRunner init(){
		return args -> {
			UserEntity userEntity = UserEntity.builder()
												.email("kev@gmail.com")
												.username("kevin")
												.password(passwordEncoder.encode("12345"))
												.roles(Set.of(RoleEntity.builder().name(ERole.valueOf(ERole.ADMIN.name())).build()))
												.build();
			
			UserEntity userEntity2 = UserEntity.builder()
												.email("angie@gmail.com")
												.username("Angie")
												.password(passwordEncoder.encode("12345"))
												.roles(Set.of(RoleEntity.builder().name(ERole.valueOf(ERole.USER.name())).build()))
												.build();
									
			UserEntity userEntity3 = UserEntity.builder()
												.email("jose@gmail.com")
												.username("Jose")
												.password(passwordEncoder.encode("12345"))
												.roles(Set.of(RoleEntity.builder().name(ERole.valueOf(ERole.INVITED.name())).build()))
												.build();

			userRepository.save(userEntity);
			userRepository.save(userEntity2);
			userRepository.save(userEntity3);
		};
	}
}
