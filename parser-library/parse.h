/*
The MIT License (MIT)

Copyright (c) 2013 Andrew Ruef

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#ifndef _PARSE_H
#define _PARSE_H
#include <cstdint>
#include <string>

#include "buffer.h"
#include "nt-headers.h"
#include "to_string.h"

#ifdef _MSC_VER
#define __typeof__(x) std::remove_reference < decltype(x) > ::type
#endif

namespace peparse {

typedef std::uint32_t RVA;
typedef std::uint64_t VA;

struct resource {
  std::string type_str;
  std::string name_str;
  std::string lang_str;
  std::uint32_t type;
  std::uint32_t name;
  std::uint32_t lang;
  std::uint32_t codepage;
  std::uint32_t RVA;
  std::uint32_t size;
  bounded_buffer *buf;

  // Default constructor
  resource() : type(0), name(0), lang(0), codepage(0), RVA(0), size(0),
      buf(nullptr) {}
  // Copy constructor
  resource(const resource &other) {
    type_str = other.type_str;
    name_str = other.name_str;
    lang_str = other.lang_str;
    type = other.type;
    name = other.name;
    lang = other.lang;
    codepage = other.codepage;
    RVA = other.RVA;
    size = other.size;
    buf = new bounded_buffer();
    *buf = *(other.buf);
  }
  // Move constructor
  resource(resource &&other) {
    if (this != &other) {
      type_str = other.type_str;
      name_str = other.name_str;
      lang_str = other.lang_str;
      type = other.type;
      name = other.name;
      lang = other.lang;
      codepage = other.codepage;
      RVA = other.RVA;
      size = other.size;
      buf = other.buf;
      other.buf = nullptr;
    }
  }
  ~resource() {
    if (buf != nullptr) {
      delete buf;
    }
  }
};

// http://msdn.microsoft.com/en-us/library/ms648009(v=vs.85).aspx
enum resource_type {
  RT_CURSOR = 1,
  RT_BITMAP = 2,
  RT_ICON = 3,
  RT_MENU = 4,
  RT_DIALOG = 5,
  RT_STRING = 6,
  RT_FONTDIR = 7,
  RT_FONT = 8,
  RT_ACCELERATOR = 9,
  RT_RCDATA = 10,
  RT_MESSAGETABLE = 11,
  RT_GROUP_CURSOR = 12, // MAKEINTRESOURCE((ULONG_PTR)(RT_CURSOR) + 11)
  RT_GROUP_ICON = 14,   // MAKEINTRESOURCE((ULONG_PTR)(RT_ICON) + 11)
  RT_VERSION = 16,
  RT_DLGINCLUDE = 17,
  RT_PLUGPLAY = 19,
  RT_VXD = 20,
  RT_ANICURSOR = 21,
  RT_ANIICON = 22,
  RT_HTML = 23,
  RT_MANIFEST = 24
};

struct parsed_pe_internal;

typedef struct _pe_header { nt_header_32 nt; } pe_header;

typedef struct _parsed_pe {
  bounded_buffer *fileBuffer;
  parsed_pe_internal *internal;
  pe_header peHeader;

  // Constructor
  _parsed_pe() : fileBuffer(nullptr), internal(nullptr) {}
  // Destructor
  ~_parsed_pe();
} parsed_pe;

// get parser error status as integer
int GetPEErr();

// get parser error status as string
std::string GetPEErrString();

// get parser error location as string
std::string GetPEErrLoc();

// get a PE parse context from a file
parsed_pe *ParsePEFromFile(const char *filePath);

// destruct a PE context
void DestructParsedPE(parsed_pe *p);

// iterate over the resources
typedef int (*iterRsrc)(void *, resource);
void IterRsrc(parsed_pe *pe, iterRsrc cb, void *cbd);

// iterate over the imports by RVA and string
typedef int (*iterVAStr)(void *, VA, std::string &, std::string &);
void IterImpVAString(parsed_pe *pe, iterVAStr cb, void *cbd);

// iterate over relocations in the PE file
typedef int (*iterReloc)(void *, VA, reloc_type);
void IterRelocs(parsed_pe *pe, iterReloc cb, void *cbd);

// Iterate over symbols (symbol table) in the PE file
typedef int (*iterSymbol)(void *,
                          std::string &,
                          uint32_t &,
                          int16_t &,
                          uint16_t &,
                          uint8_t &,
                          uint8_t &);
void IterSymbols(parsed_pe *pe, iterSymbol cb, void *cbd);

// iterate over the exports
typedef int (*iterExp)(void *, VA, std::string &, std::string &);
void IterExpVA(parsed_pe *pe, iterExp cb, void *cbd);

// iterate over sections
typedef int (*iterSec)(
    void *, VA secBase, std::string &, image_section_header, bounded_buffer *b);
void IterSec(parsed_pe *pe, iterSec cb, void *cbd);

// get byte at VA in PE
bool ReadByteAtVA(parsed_pe *pe, VA v, std::uint8_t &b);

// get entry point into PE
bool GetEntryPoint(parsed_pe *pe, VA &v);
} // namespace peparse

#endif
