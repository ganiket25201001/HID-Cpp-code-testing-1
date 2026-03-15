cmake_minimum_required(VERSION 3.22)

project(HidShield
    VERSION 0.1.0
    DESCRIPTION "Zero-Trust HID Attack Prevention Platform"
    LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
    add_compile_options(/W4 /permissive- /EHsc /guard:cf)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS NOMINMAX WIN32_LEAN_AND_MEAN)
endif()

option(ENABLE_ONNX_RUNTIME "Enable ONNX Runtime inference path" OFF)

add_executable(hidshield
    src/app/main.cpp
    src/core/orchestrator.cpp
    src/platform/usb_device_detector.cpp
    src/platform/hid_monitor.cpp
    src/platform/etw_provider.cpp
    src/security/device_fingerprint_engine.cpp
    src/security/behavioral_analyzer.cpp
    src/security/threat_classifier.cpp
    src/security/policy_engine.cpp
    src/security/remediation_engine.cpp
    src/security/model_integrity.cpp
    src/security/onnx_pipeline.cpp)

target_include_directories(hidshield PRIVATE src)

target_link_libraries(hidshield PRIVATE setupapi advapi32 bcrypt)

if(ENABLE_ONNX_RUNTIME)
    target_compile_definitions(hidshield PRIVATE ENABLE_ONNX_RUNTIME=1)
endif()
