cmake_minimum_required(VERSION 3.22)
project(gnunet_node_android LANGUAGES C)

if(NOT ANDROID)
    message(FATAL_ERROR "Use the Android NDK CMake toolchain")
endif()

set(GNUNET_NODE_ARCHIVES "" CACHE PATH "Directory containing ABI-specific Rust archives")
set(node_archive "${GNUNET_NODE_ARCHIVES}/${ANDROID_ABI}/libgnunet_node_sdk.a")
if(NOT EXISTS "${node_archive}")
    message(FATAL_ERROR "Missing GNUnet Rust archive for ${ANDROID_ABI}: ${node_archive}")
endif()

add_library(gnunet_node_sdk STATIC IMPORTED)
set_target_properties(gnunet_node_sdk PROPERTIES IMPORTED_LOCATION "${node_archive}")

add_library(gnunet_node_android SHARED node_jni.c)
target_compile_features(gnunet_node_android PRIVATE c_std_11)
target_include_directories(gnunet_node_android PRIVATE "${CMAKE_CURRENT_LIST_DIR}/../../../../sdk/include")
target_compile_options(gnunet_node_android PRIVATE -Wall -Wextra -Werror)
target_link_options(gnunet_node_android PRIVATE -Wl,--exclude-libs,ALL)
target_link_libraries(gnunet_node_android PRIVATE gnunet_node_sdk dl log m unwind)
