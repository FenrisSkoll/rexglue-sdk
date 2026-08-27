add_executable(fault_walk_synthetic_enabled
    fault_walk_synthetic_test.cpp
)
target_link_libraries(fault_walk_synthetic_enabled PRIVATE rexruntime)
target_compile_definitions(fault_walk_synthetic_enabled PRIVATE
    REXGLUE_ENABLE_FAULT_WALK=1
    FAULT_WALK_EXPECT_ENABLED=1
)
set_target_properties(fault_walk_synthetic_enabled PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY $<TARGET_FILE_DIR:rexruntime>
)
add_test(NAME fault_walk.synthetic_enabled COMMAND fault_walk_synthetic_enabled)
set_tests_properties(fault_walk.synthetic_enabled PROPERTIES
    LABELS "fault_walk;synthetic"
    TIMEOUT 30
)

add_executable(fault_walk_synthetic_disabled
    fault_walk_synthetic_test.cpp
)
target_link_libraries(fault_walk_synthetic_disabled PRIVATE rexruntime)
target_compile_definitions(fault_walk_synthetic_disabled PRIVATE
    FAULT_WALK_EXPECT_ENABLED=0
)
set_target_properties(fault_walk_synthetic_disabled PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY $<TARGET_FILE_DIR:rexruntime>
)
add_test(NAME fault_walk.synthetic_disabled COMMAND fault_walk_synthetic_disabled)
set_tests_properties(fault_walk.synthetic_disabled PROPERTIES
    LABELS "fault_walk;synthetic"
    TIMEOUT 30
)
