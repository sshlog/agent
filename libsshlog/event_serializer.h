/*
 * Copyright 2026- by CHMOD 700 LLC. All rights reserved.
 * This file is part of the SSHLog Software (SSHLog)
 * Licensed under the GNU AFFERO GENERAL PUBLIC LICENSE Version 3 (AGPLv3)
 */

#ifndef SSHLOG_EVENT_SERIALIZER_H
#define SSHLOG_EVENT_SERIALIZER_H

// Processes the event and returns JSON data
char* serialize_event(void* event_struct);

#endif // SSHLOG_EVENT_SERIALIZER_H