/*
 * Copyright, AnyWi Technologies BV, 2020,2021,2022
 */

#include <iostream>
#include <linkmanager/module_registry.h>

#include "EM9191_module.h"

extern "C" {

void init_link_plugin(void *_reg) {
	if (!_reg) {
		// Must not happen!
		std::cerr << "Bad registry, aborting." << std::endl;
		return;
	}

	auto mr = reinterpret_cast<linkmanager::module_registry*>(_reg);
	mr->register_module(std::make_shared<test_module>());
}

} // extern "C"
