package org.launchcode.techjobsauth.models.data;

import org.launchcode.techjobsauth.models.User;
import org.springframework.data.repository.CrudRepository;

public interface UserRepository extends CrudRepository<User, Integer> {
    User findByUsername(String username);
}
