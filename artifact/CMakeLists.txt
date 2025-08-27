cmake_minimum_required(VERSION 2.8.11)
project(SWE)

add_library(
	swe
	SHARED
	
	art_bls.c
	art_utils.c
	art_swe.c
	art_table.c
	art_prf.c
	art_msm.c
	art_dataio.c
)

SET_TARGET_PROPERTIES(swe PROPERTIES VERSION 1.0 SOVERSION 1)

INSTALL(TARGETS swe LIBRARY DESTINATION lib)

enable_testing()
ADD_EXECUTABLE(swe_test art_swetest.c)

TARGET_LINK_LIBRARIES(swe_test LINK_PUBLIC swe)
TARGET_LINK_LIBRARIES(swe_test LINK_PUBLIC gmssl)

ADD_TEST(NAME swe_test COMMAND swe_test)
