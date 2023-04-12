set(DEPEND_A crypto_soft)

set(PERF_SRC
    command.c
    lib.c
    nist.c
    perf.c
    sm2.c
    sm3.c 
    sm4.c 
    sha1.c 
    sha2.c 
    sha3.c 
    aes.c
)


add_executable(perf ${PERF_SRC})
target_link_libraries (perf LINK_PUBLIC ${DEPEND_A} pthread)
include_directories( ${PROJECT_SOURCE_DIR}/include )

