package alexander.SpringSecurityJWT.repositories;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import alexander.SpringSecurityJWT.models.RoleEntity;

@Repository
public interface RoleRepository extends CrudRepository<RoleEntity, Long>{

}
