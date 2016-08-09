aux_source_directory(. SRC_LIST)

set(EXECUTABLE devcrypto)

# Detect Fedora 22
if(EXISTS "/etc/fedora-release")
	file (STRINGS "/etc/fedora-release" DISTRO_STRING)
	set (DISTRO_LIST ${DISTRO_STRING})
	separate_arguments (DISTRO_LIST)
	list (GET DISTRO_LIST 2 DISTRO_NUM)
	if (${DISTRO_NUM} EQUAL 22)
		set (FEDORA_22 1)
	endif (${DISTRO_NUM} EQUAL 22)
endif(EXISTS "/etc/fedora-release")

file(GLOB HEADERS "*.h")
add_library(${EXECUTABLE} ${SRC_LIST} ${HEADERS})
if (NOT DEFINED FEDORA_22)
	add_definitions(-D_GLIBCXX_USE_CXX11_ABI=1)
else (NOT DEFINED FEDORA_22)
	message (STATUS "Fedora 22 detected - using old ABI")
endif (NOT DEFINED FEDORA_22)
eth_use(${EXECUTABLE} REQUIRED Dev::devcore Utils::scrypt Cryptopp)

if (NOT EMSCRIPTEN)
	eth_use(${EXECUTABLE} REQUIRED Utils::secp256k1)
endif ()

install( TARGETS ${EXECUTABLE} RUNTIME DESTINATION bin ARCHIVE DESTINATION lib LIBRARY DESTINATION lib )

