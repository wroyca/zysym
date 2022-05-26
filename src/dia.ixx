module;

#include <atlcomcli.h>
#include <comdef.h>
#include <comutil.h>

#include <dia2.h>
#include <diacreate.h>

#include <string>
#include <iostream>
#include <format>

export module dia;
export

namespace ZySym {

// IDia need to be globally accessible for Zydis hooks.

CComPtr<IDiaDataSource> dia_data_source;
CComPtr<IDiaSession>  dia_session;
CComPtr<IDiaSymbol> dia_global_scope;

auto get_data_from_pdb(const std::wstring &pdb)
{
  try {
    if (const auto hr = NoRegCoCreate(DIA, CLSID_DiaSource, IID_IDiaDataSource, reinterpret_cast<void**>(&dia_data_source)); FAILED(hr))
      _com_issue_error(hr);
    if (const auto hr = dia_data_source->loadDataFromPdb(pdb.c_str()); FAILED(hr))
      _com_issue_error(hr);
    if (const auto hr = dia_data_source->openSession(&dia_session); FAILED(hr))
      _com_issue_error(hr);
    if (const auto hr = dia_session->get_globalScope(&dia_global_scope); FAILED(hr))
      _com_issue_error(hr);
  }
  catch (const _com_error &e) {
    std::cerr << std::format("Oops, something unexpected happened, please check if your PDB is valid and try again. \nError: {}\n", e.ErrorMessage());
    std::quick_exit(EXIT_FAILURE);
  }
}

auto get_symbol_by_name(const wchar_t *sym_name, enum SymTagEnum sym_tag)
{
  assert(wcscmp(sym_name, L"") != 0);

  CComPtr<IDiaSymbol> children;
  CComPtr<IDiaEnumSymbols> enum_children;

  dia_global_scope->findChildren(sym_tag, nullptr, nsNone, &enum_children);
  unsigned long celt = 0;

  while (SUCCEEDED(enum_children->Next(1, &children, &celt)) && celt == 1) {
    wchar_t *name = L"";
    unsigned long rva = 0;
    unsigned long long length = 0;

    children->get_name(&name);
    children->get_relativeVirtualAddress(&rva);
    children->get_length(&length);

    // It is possible that get_name returns an empty string
    if (wcscmp(name, L"") != 0)
      SysFreeString(name);
    if (wcscmp(name, sym_name) == 0) {
      SysFreeString(name);
      return std::pair{ rva, length };
    }

    children.Release();
  }
  enum_children.Release();
}

} // namespace ZySym
