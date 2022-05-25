add_executable(ZySym
  dia.ixx
  disassemble.ixx
  main.ixx
)

target_include_directories(ZySym
PRIVATE
  "${VS}/DIA SDK/include"
)

target_link_directories(ZySym
PUBLIC
  "${VS}/DIA SDK/lib/amd64"
)

target_link_libraries(ZySym
PUBLIC
  diaguids
  Zydis
  LIEF::LIEF
)

target_link_options(ZySym
PRIVATE
  /NODEFAULTLIB:MSVCRT
)

target_compile_features(ZySym
PRIVATE
  cxx_std_23
)

target_compile_options(ZySym
PRIVATE
  /MP
  /Zi
  /Zc:strictStrings-
)

target_compile_definitions(ZySym
PRIVATE
  -DDIA=L"${VS}/DIA SDK/bin/amd64/msdia140.dll"
)
