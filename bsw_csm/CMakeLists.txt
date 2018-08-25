project (bsw_csm C)

set (TARGET_BSW_CSM ca_bsw_csm)
set (TARGET_BSW_CSM_TEST test_bsw_csm)

set (BSW_CSM_SRCS
    host/src/ca_bsw_csm.c
    host/src/bsw_csm_utils.c
    )

add_library (${TARGET_BSW_CSM} SHARED ${BSW_CSM_SRCS})

target_include_directories (${TARGET_BSW_CSM}
			   PRIVATE ta/include
			   PRIVATE include
			   PRIVATE ${OPTEE_AUTOSAR_SDK}/host_include)

target_link_libraries (${TARGET_BSW_CSM} PRIVATE teec)

install (TARGETS ${TARGET_BSW_CSM} DESTINATION ${CMAKE_INSTALL_LIBDIR})

set (BSW_CSM_TEST_SRCS
    host/test/main.c
    )

add_executable (${TARGET_BSW_CSM_TEST} ${BSW_CSM_TEST_SRCS})

target_include_directories (${TARGET_BSW_CSM_TEST}
			   PRIVATE ta/include
			   PRIVATE include
			   PRIVATE ${OPTEE_AUTOSAR_SDK}/host_include)

target_link_libraries (${TARGET_BSW_CSM_TEST} PRIVATE ${TARGET_BSW_CSM})

install (TARGETS ${TARGET_BSW_CSM_TEST} DESTINATION ${CMAKE_INSTALL_BINDIR})
