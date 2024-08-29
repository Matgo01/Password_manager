cmake_minimum_require(VERSION 3.10)

project(PasswordManagerApp)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

find_package(Qt6 REQUIRED COMPONENTS  Widgets Sql)
find_package(OpenSSL REQUIRED)

include_directories(${QtWidgets_INCLUDE_DIRS} ${Qt6Sql_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR})

set(SOURCES
    main.cpp
    login.cpp
    registration.cpp
    encryptionManager.cpp)

add_executable(PasswordManagerApp ${SOURCES})

target_link_libraries(PasswordManagerApp Qt6:.Widgets Qt6::Sql OpneSLL::SLL OpenSLL::Crypto)