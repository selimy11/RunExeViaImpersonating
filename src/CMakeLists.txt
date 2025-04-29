set(APP_NAME RunExecutable)

add_executable(
    ${APP_NAME} src/run_executable.cpp)

target_include_directories(${APP_NAME} PUBLIC include)