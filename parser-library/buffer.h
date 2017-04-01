#ifndef _BUFFER_H
#define _BUFFER_H

#include "common.h"
#include "to_string.h"

#ifdef WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

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

} // namespace peparse

#endif
