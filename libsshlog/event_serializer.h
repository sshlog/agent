/*
 * Copyright 2023- by Open Kilt LLC. All rights reserved.
 * This file is part of the SSHLog Software (SSHLog)
 * Licensed under the Redis Source Available License 2.0 (RSALv2)
 */

#ifndef SSHLOG_EVENT_SERIALIZER_H
#define SSHLOG_EVENT_SERIALIZER_H

// Processes the event and returns JSON data
char* serialize_event(void* event_struct);

#endif // SSHLOG_EVENT_SERIALIZER_H