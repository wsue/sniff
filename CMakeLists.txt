# CMake 最低版本号要求
cmake_minimum_required (VERSION 2.1)
# 项目信息
project (sniff)
set(CMAKE_C_FLAGS "-g")


include_directories(inc)
aux_source_directory(. DIR_SRCS)
aux_source_directory(main DIR_SRCS)
aux_source_directory(misc DIR_SRCS)
aux_source_directory(proto DIR_SRCS)
# 指定生成目标
add_executable(sniff ${DIR_SRCS})

find_package( ZLIB REQUIRED )
if ( ZLIB_FOUND )
    include_directories( ${ZLIB_INCLUDE_DIRS} )
    target_link_libraries( sniff ${ZLIB_LIBRARIES} )
endif( ZLIB_FOUND )
