package com.cropxapp.farm.service;

import com.cropxapp.farm.model.Farm;

import java.util.List;

public interface FarmService {
	
	List<Farm> findAll();
	Farm saveOrUpdate(Farm farm);
	void delete(Farm farm);
	Farm findByFarmName(String name);
	void deleteAll();
	List<Farm> testFilterFarm(List<Farm> farms);
}
