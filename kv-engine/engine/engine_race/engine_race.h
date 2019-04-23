// Copyright [2018] Alibaba Cloud All rights reserved
#ifndef ENGINE_RACE_ENGINE_RACE_H_
#define ENGINE_RACE_ENGINE_RACE_H_

#include <string>
#include <map>
#include <vector>
#include <utility>

#include <stdint.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>

#include "include/engine.h"


namespace polar_race {

static const uint32_t kMaxKeyLen = 32;
static const uint32_t kMaxValueLen = 4 * 1024 * 1024; // 4MB


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
  RetCode Sync();

 private:
  int fd_;
  std::string dir_;
  Location next_location_;

  RetCode OpenCurFile();
};

/********************************************
 * Door Plate
 * ******************************************/

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

    RetCode Sync();

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
int FileAppend(int fd, const char * start, size_t len);
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

/***************************************
 * Write-ahead log
 * *************************************/

class WriteAheadLog {
	public:
		explicit WriteAheadLog(const std::string &path);
		~WriteAheadLog();

		static uint8_t CalcParity(uint32_t key_size, const std::string &key, uint32_t value_size, const std::string &value);

		RetCode Init();
		RetCode Append(const std::string &key, const std::string &value, uint8_t parity);
		RetCode GetValidLogs(std::vector<std::pair<std::string, std::string>> *valid_logs); // vector<pair<key, value>>
		RetCode DisableAllLogs();
		inline RetCode SyncLog();
	private:
		std::string dir_;
		int fd_;
		int log_entry_cnt_;

};

/****************************************
 * KV-Engine
 * **************************************/

class EngineRace : public Engine  {
 public:
  static RetCode Open(const std::string& name, Engine** eptr);

  explicit EngineRace(const std::string& dir):
	  mu_(PTHREAD_MUTEX_INITIALIZER),
	  log_mu_(PTHREAD_MUTEX_INITIALIZER),
	  db_lock_(NULL),
	  plate_(dir),
	  store_(dir),
	  write_ahead_log_(dir){
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
  pthread_mutex_t log_mu_;
  FileLock * db_lock_;
  DoorPlate plate_;
  DataStore store_;
  WriteAheadLog write_ahead_log_;

};

}  // namespace polar_race

#endif  // ENGINE_RACE_ENGINE_RACE_H_
