package com.cropxapp.farm.repository;

import com.cropxapp.farm.model.Farm;
import org.springframework.data.jpa.repository.JpaRepository;

public interface FarmRepository extends JpaRepository<Farm, Long> {
	
	public Farm findByName(String name);

}
