project(fanotify)

cmake_minimum_required (VERSION 2.6) 

find_package (Threads)

add_subdirectory(lib)

set(MY_SOURCES main.c)

add_executable(fanotify ${MY_SOURCES})
target_link_libraries(fanotify ${CMAKE_THREAD_LIBS_INIT})
target_link_libraries(fanotify library)
