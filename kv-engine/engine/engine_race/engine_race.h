// Copyright [2018] Alibaba Cloud All rights reserved
#ifndef ENGINE_RACE_ENGINE_RACE_H_
#define ENGINE_RACE_ENGINE_RACE_H_

#include <string>
#include <map>
#include <vector>

#include <stdint.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>

#include "include/engine.h"


namespace polar_race {

/*******************************************
 * Data Store
 *******************************************/

struct Location {
  Location() : file_no(0), offset(0), len(0) {
  }
  uint32_t file_no;
  uint32_t offset;
  uint32_t len;
};

class DataStore  {
 public:
  explicit DataStore(const std::string dir)
    : fd_(-1), dir_(dir) {}

  ~DataStore() {
    if (fd_ > 0) {
      close(fd_);
    }
  }

  RetCode Init();
  RetCode Read(const Location& l, std::string* value);
  RetCode Append(const std::string& value, Location* location);

 private:
  int fd_;
  std::string dir_;
  Location next_location_;

  RetCode OpenCurFile();
};

/********************************************
 * Door Plate
 * ******************************************/

static const uint32_t kMaxKeyLen = 32;

struct Item {
  Item() : key_size(0), in_use(0) {
  }
  Location location;
  char key[kMaxKeyLen];
  uint32_t key_size;
  uint8_t in_use;
};

// Hash index for key
class DoorPlate  {
 public:
    explicit DoorPlate(const std::string& path);
    ~DoorPlate();

    RetCode Init();

    RetCode AddOrUpdate(const std::string& key, const Location& l);

    RetCode Find(const std::string& key, Location *location);

    RetCode GetRangeLocation(const std::string& lower, const std::string& upper,
        std::map<std::string, Location> *locations);

 private:
    std::string dir_;
    int fd_;
    Item *items_;

    int CalcIndex(const std::string& key);
};

/**************************
 * Utils 
 **************************/

// Hash
uint32_t StrHash(const char* s, int size);

// Env
int GetDirFiles(const std::string& dir, std::vector<std::string>* result);
int GetFileLength(const std::string& file);
int FileAppend(int fd, const std::string& value);
bool FileExists(const std::string& path);

// FileLock
class FileLock  {
 public:
    FileLock() {}
    virtual ~FileLock() {}

    int fd_;
    std::string name_;

 private:
    // No copying allowed
    FileLock(const FileLock&);
    void operator=(const FileLock&);
};

int LockFile(const std::string& f, FileLock** l);
int UnlockFile(FileLock* l);

/****************************************
 * KV-Engine
 * **************************************/

class EngineRace : public Engine  {
 public:
  static RetCode Open(const std::string& name, Engine** eptr);

  explicit EngineRace(const std::string& dir):
	  mu_(PTHREAD_MUTEX_INITIALIZER),
	  db_lock_(NULL),
	  plate_(dir),
	  store_(dir) {
	  }

  ~EngineRace();

  RetCode Write(const PolarString& key,
      const PolarString& value) override;

  RetCode Read(const PolarString& key,
      std::string* value) override;

  /*
   * NOTICE: Implement 'Range' in quarter-final,
   *         you can skip it in preliminary.
   */
  RetCode Range(const PolarString& lower,
      const PolarString& upper,
      Visitor &visitor) override;

 private: 
  pthread_mutex_t mu_;
  FileLock * db_lock_;
  DoorPlate plate_;
  DataStore store_;

};

}  // namespace polar_race

#endif  // ENGINE_RACE_ENGINE_RACE_H_
