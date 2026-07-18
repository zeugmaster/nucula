# The following five lines of boilerplate have to be in your project's
# CMakeLists in this exact order for cmake to work correctly
cmake_minimum_required(VERSION 3.16)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(nucula)

# Speed-critical components get -O2 on top of the project-wide -Os (the
# trailing flag wins): mbedTLS carries the TLS handshake that dominates
# payment latency. Flash headroom is ample (~40% of the app partition).
foreach(lib mbedtls mbedcrypto mbedx509)
    if(TARGET ${lib})
        target_compile_options(${lib} PRIVATE -O2)
    endif()
endforeach()
