package com.cropxapp.farm.service;

import com.cropxapp.farm.model.Farm;
import com.cropxapp.farm.repository.FarmRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.access.prepost.PreFilter;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@Transactional
public class FarmServiceImpl implements FarmService {
	
	@Autowired
    private FarmRepository FarmRepository;

	@Override
	public List<Farm> findAll() {
		return FarmRepository.findAll();
	}

	@Override
	public Farm saveOrUpdate(Farm t) {
		return FarmRepository.save(t);
	}

	@Override
	public void delete(Farm t) {
		FarmRepository.delete(t);
	}

	@Override
	public Farm findByFarmName(String name) {
		return FarmRepository.findByName(name);
	}

	@Override
	public void deleteAll() {
		FarmRepository.deleteAll();
	}

	@PreAuthorize("hasRole('ROLE_ADMIN')")
	@PreFilter("hasPermission(filterObject, 'administration')")
	public List<Farm> testFilterFarm(List<Farm> Farms) {
		return Farms;
	}
}
