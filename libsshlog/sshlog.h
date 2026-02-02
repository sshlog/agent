/*
 * Copyright 2026- by CHMOD 700 LLC. All rights reserved.
 * This file is part of the SSHLog Software (SSHLog)
 * Licensed under the GNU AFFERO GENERAL PUBLIC LICENSE Version 3 (AGPLv3)
 */


#ifndef SSHLOG_API_H
#define SSHLOG_API_H

#ifdef __cplusplus
extern "C" {
#endif

typedef void SSHLOG;

enum SSHLOG_LOG_LEVEL {
  LOG_OFF = 0, // default
  LOG_FATAL = 1,
  LOG_ERROR = 2,
  LOG_WARNING = 3,
  LOG_INFO = 4,
  LOG_DEBUG = 5,
  LOG_VERBOSE = 6
};
struct sshlog_options {
  // Log messages (if enabled) will be emitted as events on the event poll
  SSHLOG_LOG_LEVEL log_level;
};

/**
 * Initializes the SSHLog library
 *
 * When finished with the library, make sure to release the object
 *
 * see also sshlog_release()
 * @return An instance of SSHLog that can be used with other functions
 */
SSHLOG* sshlog_init(sshlog_options* options);

sshlog_options sshlog_get_default_options();

// Returns JSON encoded event data
char* sshlog_event_poll(SSHLOG* instance, int timeout_ms);

// Returns 0 if ok, 1 otherwise
int sshlog_is_ok(SSHLOG* instance);

// Releases the memory for the event data string
void sshlog_event_release(char* json_event_data);

void sshlog_release(SSHLOG* instance);

#ifdef __cplusplus
}
#endif

#endif /* SSHLOG_API_H */
