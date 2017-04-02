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

#ifndef _BUFFER_H
#define _BUFFER_H

#include "to_string.h"

#ifdef WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

#define PE_ERR(x)           \
  err = (pe_err) x;         \
  err_loc.assign(__func__); \
  err_loc += ":" + to_string<std::uint32_t>(__LINE__, dec);

#define READ_WORD(b, o, inst, member)                                     \
  if (!readWord(b, o + _offset(__typeof__(inst), member), inst.member)) { \
    PE_ERR(PEERR_READ);                                                   \
    return false;                                                         \
  }

#define READ_DWORD(b, o, inst, member)                                     \
  if (!readDword(b, o + _offset(__typeof__(inst), member), inst.member)) { \
    PE_ERR(PEERR_READ);                                                    \
    return false;                                                          \
  }

#define READ_QWORD(b, o, inst, member)                                     \
  if (!readQword(b, o + _offset(__typeof__(inst), member), inst.member)) { \
    PE_ERR(PEERR_READ);                                                    \
    return false;                                                          \
  }

#define READ_DWORD_PTR(b, o, inst, member)                                   \
  if (!readDword(b, o + _offset(__typeof__(*inst), member), inst->member)) { \
    PE_ERR(PEERR_READ);                                                      \
    return false;                                                            \
  }

#define READ_BYTE(b, o, inst, member)                                     \
  if (!readByte(b, o + _offset(__typeof__(inst), member), inst.member)) { \
    PE_ERR(PEERR_READ);                                                   \
    return false;                                                         \
  }

/* This variant returns NULL instead of false. */
#define READ_DWORD_NULL(b, o, inst, member)                                \
  if (!readDword(b, o + _offset(__typeof__(inst), member), inst.member)) { \
    PE_ERR(PEERR_READ);                                                    \
    return NULL;                                                           \
  }

namespace peparse {

struct buffer_detail {
#ifdef WIN32
  HANDLE file;
  HANDLE sec;
#else
  int fd;
#endif
};

typedef struct _bounded_buffer {
  std::uint8_t *buf;
  std::uint32_t bufLen;
  bool copy;
  buffer_detail *detail;

  // Constructor
  _bounded_buffer() : buf(nullptr), bufLen(0), copy(false), detail(nullptr) {}
  // Destructor
  ~_bounded_buffer() {
    if (!copy) {
#ifdef WIN32
      UnmapViewOfFile(buf);
      CloseHandle(detail->sec);
      CloseHandle(detail->file);
#else
      munmap(buf, bufLen);
      close(detail->fd);
#endif
    }

    if (detail != nullptr) {
      delete detail;
    }
  }
} bounded_buffer;

bool readByte(bounded_buffer *b, std::uint32_t offset, std::uint8_t &out);
bool readWord(bounded_buffer *b, std::uint32_t offset, std::uint16_t &out);
bool readDword(bounded_buffer *b, std::uint32_t offset, std::uint32_t &out);
bool readQword(bounded_buffer *b, std::uint32_t offset, std::uint64_t &out);

bounded_buffer *readFileToFileBuffer(const char *filePath);
bounded_buffer *
splitBuffer(bounded_buffer *b, std::uint32_t from, std::uint32_t to);
uint64_t bufLen(bounded_buffer *b);

enum pe_err {
  PEERR_NONE = 0,
  PEERR_MEM = 1,
  PEERR_HDR = 2,
  PEERR_SECT = 3,
  PEERR_RESC = 4,
  PEERR_SECTVA = 5,
  PEERR_READ = 6,
  PEERR_OPEN = 7,
  PEERR_STAT = 8,
  PEERR_MAGIC = 9
};

} // namespace peparse

#endif
