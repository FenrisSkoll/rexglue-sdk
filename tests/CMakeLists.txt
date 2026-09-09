# ReXGlue Tests
# Test infrastructure for PPC instruction validation and unit tests

# Unit tests for core components
add_subdirectory(unit)

if(WIN32)
    add_subdirectory(fault_walk)
endif()

# PPC instruction tests (requires PPC toolchain)
add_subdirectory(ppc)
