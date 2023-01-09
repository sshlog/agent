#ifndef SSHBOUNCER_EVENT_SERIALIZER_H
#define SSHBOUNCER_EVENT_SERIALIZER_H

// Processes the event and returns JSON data
char* serialize_event(void* event_struct);

#endif // SSHBOUNCER_EVENT_SERIALIZER_H