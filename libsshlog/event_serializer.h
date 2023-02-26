#ifndef SSHLOG_EVENT_SERIALIZER_H
#define SSHLOG_EVENT_SERIALIZER_H

// Processes the event and returns JSON data
char* serialize_event(void* event_struct);

#endif // SSHLOG_EVENT_SERIALIZER_H