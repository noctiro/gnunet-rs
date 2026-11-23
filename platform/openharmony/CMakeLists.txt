cmake_minimum_required(VERSION 3.16)
project(gnunet_node LANGUAGES CXX)

set(GNUNET_RUST_ARCHIVE "" CACHE FILEPATH "Release gnunet-node-sdk static archive for OHOS_ARCH")
set(GNUNET_SDK_INCLUDE_DIR "${CMAKE_CURRENT_LIST_DIR}/../sdk/include" CACHE PATH "GNUnet node C ABI headers")
set(GNUNET_RUST_NATIVE_LIBRARIES "dl;m" CACHE STRING "Native libraries required by the Rust archive")

if(NOT OHOS_ARCH OR NOT EXISTS "${GNUNET_RUST_ARCHIVE}")
  message(FATAL_ERROR "Use build-sdk.sh to configure the OpenHarmony toolchain and Rust archive for OHOS_ARCH")
endif()

add_library(gnunet_node_rust STATIC IMPORTED)
set_target_properties(gnunet_node_rust PROPERTIES IMPORTED_LOCATION "${GNUNET_RUST_ARCHIVE}")

add_library(gnunet_node SHARED native/node.cpp)
set_target_properties(gnunet_node PROPERTIES CXX_VISIBILITY_PRESET hidden VISIBILITY_INLINES_HIDDEN YES)
target_compile_features(gnunet_node PRIVATE cxx_std_20)
target_compile_options(gnunet_node PRIVATE -fexceptions)
target_include_directories(gnunet_node PRIVATE "${GNUNET_SDK_INCLUDE_DIR}")
target_link_options(gnunet_node PRIVATE -Wl,--no-undefined -Wl,--exclude-libs,ALL)
target_link_libraries(gnunet_node PRIVATE gnunet_node_rust libace_napi.z.so ${GNUNET_RUST_NATIVE_LIBRARIES})
install(TARGETS gnunet_node LIBRARY DESTINATION "libs/${OHOS_ARCH}")
