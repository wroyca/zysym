set(sources
  ZySym.cpp
)
set(headers
  ${PROJECT_SOURCE_DIR}/include/ZySym/ZySym
)

# Map extensionless files to Microsoft Visual C++
set_source_files_properties(${headers}
PROPERTIES
  CXX HEADER_FILE_ONLY
)

add_executable(ZySym
  ${sources}
  ${headers}
)

target_include_directories(ZySym
PUBLIC
  $<INSTALL_INTERFACE:include>
  $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>

PRIVATE
  "${VS}/DIA SDK/include"
)

target_link_directories(ZySym
PUBLIC
  "${VS}/DIA SDK/lib"
)

target_link_libraries(ZySym
PUBLIC
  diaguids
  Zydis
)

target_compile_features(ZySym
PRIVATE
  cxx_std_23
)

target_compile_options(ZySym
PRIVATE
  /MP
  /Zi
)
