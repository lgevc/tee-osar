project (bsw_storage C)

set (TARGET_BSW_STORAGE ca_bsw_storage)
set (TARGET_BSW_STORAGE_TEST test_bsw_storage)

set (BSW_STORAGE_SRCS
    host/src/ca_bsw_storage.c
    )

add_library (${TARGET_BSW_STORAGE} SHARED ${BSW_STORAGE_SRCS})

target_include_directories (${TARGET_BSW_STORAGE}
			   PRIVATE ta/include
			   PRIVATE include
			   PRIVATE ${OPTEE_AUTOSAR_SDK}/host_include)

target_link_libraries (${TARGET_BSW_STORAGE} PRIVATE teec)

install (TARGETS ${TARGET_BSW_STORAGE} DESTINATION ${CMAKE_INSTALL_LIBDIR})

set (BSW_STORAGE_TEST_SRCS
    host/test/main.c
    )

add_executable (${TARGET_BSW_STORAGE_TEST} ${BSW_STORAGE_TEST_SRCS})

target_include_directories (${TARGET_BSW_STORAGE_TEST}
			   PRIVATE ta/include
			   PRIVATE include
			   PRIVATE ${OPTEE_AUTOSAR_SDK}/host_include)

target_link_libraries (${TARGET_BSW_STORAGE_TEST} PRIVATE ${TARGET_BSW_STORAGE})

install (TARGETS ${TARGET_BSW_STORAGE_TEST} DESTINATION ${CMAKE_INSTALL_BINDIR})
