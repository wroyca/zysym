import dia;
import disassemble;

#include <iostream>

auto wmain(int argc, wchar_t* argv[]) -> int
{
  if (argc != 3) {
    std::cerr << "Usage: <pdb> <symbol> \n";
    return -1;
  }

  ZySym::get_data_from_pdb(argv[1]);
  ZySym::zydis_decode(argv[1], argv[2]);
}
