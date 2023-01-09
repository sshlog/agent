
#ifndef SSHBOUNCER_API_H
#define SSHBOUNCER_API_H

#ifdef __cplusplus
extern "C" {
#endif

typedef void SSHBOUNCER;

enum SSHBOUNCER_LOG_LEVEL {
  LOG_OFF = 0, // default
  LOG_FATAL = 1,
  LOG_ERROR = 2,
  LOG_WARNING = 3,
  LOG_INFO = 4,
  LOG_DEBUG = 5,
  LOG_VERBOSE = 6
};
struct sshbouncer_options {
  // Log messages (if enabled) will be emitted as events on the event poll
  SSHBOUNCER_LOG_LEVEL log_level;
};

/**
 * Initializes the SSHBouncer library
 *
 * When finished with the library, make sure to release the object
 *
 * see also sshbouncer_release()
 * @return An instance of SSHBouncer that can be used with other functions
 */
SSHBOUNCER* sshbouncer_init(sshbouncer_options* options);

sshbouncer_options sshbouncer_get_default_options();

// Returns JSON encoded event data
char* sshbouncer_event_poll(SSHBOUNCER* instance, int timeout_ms);

// Returns 0 if ok, 1 otherwise
int sshbouncer_is_ok(SSHBOUNCER* instance);

// Releases the memory for the event data string
void sshbouncer_event_release(char* json_event_data);

void sshbouncer_release(SSHBOUNCER* instance);

#ifdef __cplusplus
}
#endif

#endif /* SSHBOUNCER_API_H */
