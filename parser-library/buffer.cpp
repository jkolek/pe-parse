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

#include "buffer.h"
#include <fstream>
#include <string.h>

#ifdef WIN32
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

using namespace std;

namespace peparse {

extern ::uint32_t err;
extern ::string err_loc;

bool readByte(bounded_buffer *b, ::uint32_t offset, ::uint8_t &out) {
  if (b == nullptr) {
    return false;
  }

  if (offset >= b->bufLen) {
    return false;
  }

  ::uint8_t *tmp = (b->buf + offset);
  out = *tmp;

  return true;
}

// TODO: perform endian swap as needed
bool readWord(bounded_buffer *b, ::uint32_t offset, ::uint16_t &out) {
  if (b == nullptr) {
    return false;
  }

  if (offset >= b->bufLen) {
    return false;
  }

  ::uint16_t *tmp = reinterpret_cast<uint16_t *>(b->buf + offset);
  out = *tmp;

  return true;
}

// TODO: perform endian swap as needed
bool readDword(bounded_buffer *b, ::uint32_t offset, ::uint32_t &out) {
  if (b == nullptr) {
    return false;
  }

  if (offset >= b->bufLen) {
    return false;
  }

  ::uint32_t *tmp = reinterpret_cast<uint32_t *>(b->buf + offset);
  out = *tmp;

  return true;
}

// TODO: perform endian swap as needed
bool readQword(bounded_buffer *b, ::uint32_t offset, ::uint64_t &out) {
  if (b == nullptr) {
    return false;
  }

  if (offset >= b->bufLen) {
    return false;
  }

  ::uint64_t *tmp = reinterpret_cast<uint64_t *>(b->buf + offset);
  out = *tmp;

  return true;
}

bounded_buffer *readFileToFileBuffer(const char *filePath) {
#ifdef WIN32
  HANDLE h = CreateFileA(filePath,
                         GENERIC_READ,
                         FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                         nullptr,
                         OPEN_EXISTING,
                         FILE_ATTRIBUTE_NORMAL,
                         nullptr);
  if (h == INVALID_HANDLE_VALUE) {
    return nullptr;
  }

  DWORD fileSize = GetFileSize(h, nullptr);

  if (fileSize == INVALID_FILE_SIZE) {
    CloseHandle(h);
    return nullptr;
  }

#else
  // only where we have mmap / open / etc
  int fd = open(filePath, O_RDONLY);

  if (fd == -1) {
    PE_ERR(PEERR_OPEN);
    return nullptr;
  }
#endif

  // make a buffer object
  bounded_buffer *p = new (std::nothrow) bounded_buffer();

  if (p == nullptr) {
    PE_ERR(PEERR_MEM);
    return nullptr;
  }

  memset(p, 0, sizeof(bounded_buffer));
  buffer_detail *d = new (std::nothrow) buffer_detail();

  if (d == nullptr) {
    delete p;
    PE_ERR(PEERR_MEM);
    return nullptr;
  }
  memset(d, 0, sizeof(buffer_detail));
  p->detail = d;

// only where we have mmap / open / etc
#ifdef WIN32
  p->detail->file = h;

  HANDLE hMap = CreateFileMapping(h, nullptr, PAGE_READONLY, 0, 0, nullptr);

  if (hMap == nullptr) {
    CloseHandle(h);
    PE_ERR(PEERR_MEM);
    return nullptr;
  }

  p->detail->sec = hMap;

  LPVOID ptr = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);

  if (ptr == nullptr) {
    PE_ERR(PEERR_MEM);
    return nullptr;
  }

  p->buf = (::uint8_t *) ptr;
  p->bufLen = fileSize;
  p->copy = false;
#else
  p->detail->fd = fd;

  struct stat s = {0};

  if (fstat(fd, &s) != 0) {
    close(fd);
    delete d;
    delete p;
    PE_ERR(PEERR_STAT);
    return nullptr;
  }

  void *maddr = mmap(nullptr, s.st_size, PROT_READ, MAP_SHARED, fd, 0);

  if (maddr == MAP_FAILED) {
    close(fd);
    delete d;
    delete p;
    PE_ERR(PEERR_MEM);
    return nullptr;
  }

  p->buf = reinterpret_cast<uint8_t *>(maddr);
  p->bufLen = s.st_size;
  p->copy = false;
#endif

  return p;
}

// split buffer inclusively from from to to by offset
bounded_buffer *splitBuffer(bounded_buffer *b, ::uint32_t from, ::uint32_t to) {
  if (b == nullptr) {
    return nullptr;
  }

  // safety checks
  if (to < from || to > b->bufLen) {
    return nullptr;
  }

  // make a new buffer
  bounded_buffer *newBuff = new (std::nothrow) bounded_buffer();

  if (newBuff == nullptr) {
    return nullptr;
  }

  newBuff->copy = true;
  newBuff->buf = b->buf + from;
  newBuff->bufLen = (to - from);

  return newBuff;
}

uint64_t bufLen(bounded_buffer *b) {
  return b->bufLen;
}
} // namespace peparse
