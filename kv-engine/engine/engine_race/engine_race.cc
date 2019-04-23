// Copyright [2018] Alibaba Cloud All rights reserved
#include <utility>
#include <iostream>

#include <dirent.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/mman.h>

#include "engine_race.h"

namespace polar_race {

/*******************************************************
 * Data Store
 *******************************************************/

static const char kDataFilePrefix[] = "DATA_";
static const int kDataFilePrefixLen = 5;
static const int kSingleFileSize = 1024 * 1024 * 100;

static std::string FileName(const std::string &dir, uint32_t fileno) {
  return dir + "/" + kDataFilePrefix + std::to_string(fileno);
}

RetCode DataStore::Init() {
  if (!FileExists(dir_)
      && 0 != mkdir(dir_.c_str(), 0755)) {
    return kIOError;
  }

  std::vector<std::string> files;
  if (0 != GetDirFiles(dir_, &files)) {
    return kIOError;
  }

  uint32_t last_no = 0;
  uint32_t cur_offset = 0;

  // Get the last data file no
  std::string sindex;
  std::vector<std::string>::iterator it;
  for (it = files.begin(); it != files.end(); ++it) {
    if ((*it).compare(0, kDataFilePrefixLen, kDataFilePrefix) != 0) {
      continue;
    }
    sindex = (*it).substr(kDataFilePrefixLen);
    if (std::stoul(sindex) > last_no) {
      last_no = std::stoi(sindex);
    }
  }

  // Get last data file offset
  int len = GetFileLength(FileName(dir_, last_no));
  if (len > 0) {
    cur_offset = len;
  }

  next_location_.file_no = last_no;
  next_location_.offset = cur_offset;

  // Open file
  return OpenCurFile();
}

RetCode DataStore::Append(const std::string& value, Location* location) {
  if (value.size() > kSingleFileSize) {
    return kInvalidArgument;
  }

  if (next_location_.offset + value.size() > kSingleFileSize) {
    // Swtich to new file
    close(fd_);
    next_location_.file_no += 1;
    next_location_.offset = 0;
    OpenCurFile();
  }

  // Append write
  if (0 != FileAppend(fd_, value)) {
    return kIOError;
  }
  location->file_no = next_location_.file_no;
  location->offset = next_location_.offset;
  location->len = value.size();

  next_location_.offset += location->len;
  return kSucc;
}

RetCode DataStore::Read(const Location& l, std::string* value) {
  int fd = open(FileName(dir_, l.file_no).c_str(), O_RDONLY, 0644);
  if (fd < 0) {
    return kIOError;
  }
  lseek(fd, l.offset, SEEK_SET);

  char* buf = new char[l.len]();
  char* pos = buf;
  uint32_t value_len = l.len;

  while (value_len > 0) {
    ssize_t r = read(fd, pos, value_len);
    if (r < 0) {
      if (errno == EINTR) {
        continue;  // Retry
      }
      close(fd);
      return kIOError;
    }
    pos += r;
    value_len -= r;
  }
  *value = std::string(buf, l.len);

  delete buf;
  close(fd);
  return kSucc;
}

RetCode DataStore::OpenCurFile() {
  std::string file_name = FileName(dir_, next_location_.file_no);
  int fd = open(file_name.c_str(), O_APPEND | O_WRONLY | O_CREAT, 0644);
  if (fd < 0) {
    return kIOError;
  }
  fd_ = fd;
  return kSucc;
}

/**********************************************************
 * Door Plate
 * ********************************************************/

static const uint32_t kMaxDoorCnt = 1024 * 1024 * 32;
static const char kMetaFileName[] = "META";
static const int kMaxRangeBufCount = kMaxDoorCnt;

static bool ItemKeyMatch(const Item &item, const std::string& target) {
  if (target.size() != item.key_size
      || memcmp(item.key, target.data(), item.key_size) != 0) {
    // Conflict
    return false;
  }
  return true;
}

static bool ItemTryPlace(const Item &item, const std::string& target) {
  if (item.in_use == 0) {
    return true;
  }
  return ItemKeyMatch(item, target);
}

DoorPlate::DoorPlate(const std::string& path)
  : dir_(path),
  fd_(-1),
  items_(NULL) {
  }

RetCode DoorPlate::Init() {
  bool new_create = false;
  const int map_size = kMaxDoorCnt * sizeof(Item);

  if (!FileExists(dir_)
      && 0 != mkdir(dir_.c_str(), 0755)) {
    return kIOError;
  }

  std::string path = dir_ + "/" + kMetaFileName;
  int fd = open(path.c_str(), O_RDWR, 0644);
  if (fd < 0 && errno == ENOENT) {
    // not exist, then create
    fd = open(path.c_str(), O_RDWR | O_CREAT, 0644);
    if (fd >= 0) {
      new_create = true;
      if (posix_fallocate(fd, 0, map_size) != 0) {
        std::cerr << "posix_fallocate failed: " << strerror(errno) << std::endl;
        close(fd);
        return kIOError;
      }
    }
  }
  if (fd < 0) {
    return kIOError;
  }
  fd_ = fd;

  void* ptr = mmap(NULL, map_size, PROT_READ | PROT_WRITE,
      MAP_SHARED, fd_, 0);
  if (ptr == MAP_FAILED) {
    std::cerr << "MAP_FAILED: " << strerror(errno) << std::endl;
    close(fd);
    return kIOError;
  }
  if (new_create) {
    memset(ptr, 0, map_size);
  }

  items_ = reinterpret_cast<Item*>(ptr);
  return kSucc;
}

DoorPlate::~DoorPlate() {
  if (fd_ > 0) {
    const int map_size = kMaxDoorCnt * sizeof(Item);
    munmap(items_, map_size);
    close(fd_);
  }
}

// Very easy hash table, which deal conflict only by try the next one
int DoorPlate::CalcIndex(const std::string& key) {
  uint32_t jcnt = 0;
  int index = StrHash(key.data(), key.size()) % kMaxDoorCnt;
  while (!ItemTryPlace(*(items_ + index), key)
      && ++jcnt < kMaxDoorCnt) {
    index = (index + 1) % kMaxDoorCnt;
  }

  if (jcnt == kMaxDoorCnt) {
    // full
    return -1;
  }
  return index;
}

RetCode DoorPlate::AddOrUpdate(const std::string& key, const Location& l) {
  if (key.size() > kMaxKeyLen) {
    return kInvalidArgument;
  }

  int index = CalcIndex(key);
  if (index < 0) {
    return kFull;
  }

  Item* iptr = items_ + index;
  if (iptr->in_use == 0) {
    // new item
    memcpy(iptr->key, key.data(), key.size());
    iptr->key_size = key.size();
    iptr->in_use = 1;  // Place
  }
  iptr->location = l;
  return kSucc;
}

RetCode DoorPlate::Find(const std::string& key, Location *location) {
  int index = CalcIndex(key);
  if (index < 0
      || !ItemKeyMatch(*(items_ + index), key)) {
    return kNotFound;
  }

  *location = (items_ + index)->location;
  return kSucc;
}

RetCode DoorPlate::GetRangeLocation(const std::string& lower,
    const std::string& upper,
    std::map<std::string, Location> *locations) {
  int count = 0;
  for (Item *it = items_ + kMaxDoorCnt - 1; it >= items_; it--) {
    if (!it->in_use) {
      continue;
    }
    std::string key(it->key, it->key_size);
    if ((key >= lower || lower.empty())
        && (key < upper || upper.empty())) {
      locations->insert(std::pair<std::string, Location>(key, it->location));
      if (++count > kMaxRangeBufCount) {
        return kOutOfMemory;
      }
    }
  }
  return kSucc;
}

/***************************************************
 * Utils
 * *************************************************/

static const int kA = 54059;  // a prime
static const int kB = 76963;  // another prime
static const int kFinish = 37;  // also prime
uint32_t StrHash(const char* s, int size) {
  uint32_t h = kFinish;
  while (size > 0) {
    h = (h * kA) ^ (s[0] * kB);
    s++;
    size--;
  }
  return h;
}

int GetDirFiles(const std::string& dir, std::vector<std::string>* result) {
  int res = 0;
  result->clear();
  DIR* d = opendir(dir.c_str());
  if (d == NULL) {
    return errno;
  }
  struct dirent* entry;
  while ((entry = readdir(d)) != NULL) {
    if (strcmp(entry->d_name, "..") == 0 || strcmp(entry->d_name, ".") == 0) {
      continue;
    }
    result->push_back(entry->d_name);
  }
  closedir(d);
  return res;
}

int GetFileLength(const std::string& file) {
  struct stat stat_buf;
  int rc = stat(file.c_str(), &stat_buf);
  return rc == 0 ? stat_buf.st_size : -1;
}

int FileAppend(int fd, const std::string& value) {
  if (fd < 0) {
    return -1;
  }
  size_t value_len = value.size();
  const char* pos = value.data();
  while (value_len > 0) {
    ssize_t r = write(fd, pos, value_len);
    if (r < 0) {
      if (errno == EINTR) {
        continue;  // Retry
      }
      return -1;
    }
    pos += r;
    value_len -= r;
  }
  return 0;
}

bool FileExists(const std::string& path) {
  return access(path.c_str(), F_OK) == 0;
}

static int LockOrUnlock(int fd, bool lock) {
  errno = 0;
  struct flock f;
  memset(&f, 0, sizeof(f));
  f.l_type = (lock ? F_WRLCK : F_UNLCK);
  f.l_whence = SEEK_SET;
  f.l_start = 0;
  f.l_len = 0;        // Lock/unlock entire file
  return fcntl(fd, F_SETLK, &f);
}

int LockFile(const std::string& fname, FileLock** lock) {
  *lock = NULL;
  int result = 0;
  int fd = open(fname.c_str(), O_RDWR | O_CREAT, 0644);
  if (fd < 0) {
    result = errno;
  } else if (LockOrUnlock(fd, true) == -1) {
    result = errno;
    close(fd);
  } else {
    FileLock* my_lock = new FileLock;
    my_lock->fd_ = fd;
    my_lock->name_ = fname;
    *lock = my_lock;
  }
  return result;
}

int UnlockFile(FileLock* lock) {
  int result = 0;
  if (LockOrUnlock(lock->fd_, false) == -1) {
    result = errno;
  }
  close(lock->fd_);
  delete lock;
  return result;
}



/************************************************************
 * KV-Engine
 ************************************************************/

static const char kLockFile[] = "LOCK";

RetCode Engine::Open(const std::string& name, Engine** eptr) {
  return EngineRace::Open(name, eptr);
}

Engine::~Engine() {
}

/*
 * Complete the functions below to implement you own engine
 */

// 1. Open engine
RetCode EngineRace::Open(const std::string& name, Engine** eptr) {
  *eptr = NULL;
  EngineRace *engine_race = new EngineRace(name);

  // TODO 
  // 1. check the log to determine if there is some pending write operation
  
  RetCode ret = engine_race->plate_.Init();
  if (ret != kSucc) {
	  delete engine_race;
	  return ret;
  }

  ret = engine_race->store_.Init();
  if (ret != kSucc) {
	  delete engine_race;
	  return ret;
  }

  if (LockFile(name + "/" + kLockFile, &(engine_race->db_lock_)) != 0) {
	  delete engine_race;
	  return kIOError;
  }

  *eptr = engine_race;
  return kSucc;
}

// 2. Close engine
EngineRace::~EngineRace() {
	if (db_lock_) {
		UnlockFile(db_lock_);
	}
}

// 3. Write a key-value pair into engine
RetCode EngineRace::Write(const PolarString& key, const PolarString& value) {
  // TODO
  // 1. added fsync && msync call to make sure that all modification arrive at the disk in time
  // 2. write the WAL before perform actual write operation
  // 3. disable the log after write operation
  
  pthread_mutex_lock(&mu_);
  Location location;
  RetCode ret = store_.Append(value.ToString(), &location);
  if (ret == kSucc) {
	  ret = plate_.AddOrUpdate(key.ToString(), location);
  }
  pthread_mutex_unlock(&mu_);

  return ret;
}

// 4. Read value of a key
RetCode EngineRace::Read(const PolarString& key, std::string* value) {
  // TODO 
  // simply the same as the sample call
  
  pthread_mutex_lock(&mu_);
  Location location;
  RetCode ret = plate_.Find(key.ToString(), &location);
  if (ret == kSucc) {
	  value->clear();
	  ret = store_.Read(location, value);
  }
  pthread_mutex_unlock(&mu_);

  return ret;
}

/*
 * NOTICE: Implement 'Range' in quarter-final,
 *         you can skip it in preliminary.
 */
// 5. Applies the given Vistor::Visit function to the result
// of every key-value pair in the key range [first, last),
// in order
// lower=="" is treated as a key before all keys in the database.
// upper=="" is treated as a key after all keys in the database.
// Therefore the following call will traverse the entire database:
//   Range("", "", visitor)
RetCode EngineRace::Range(const PolarString& lower, const PolarString& upper,
    Visitor &visitor) {
	// TODO since this API is optional, we will not implement it.
  return kSucc;
}

}  // namespace polar_race
