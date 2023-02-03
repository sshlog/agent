#ifndef SSHTRACE_HEAP_H
#define SSHTRACE_HEAP_H

#include "sshtrace_events.h"
#include "sshtrace_types.h"
#include "vmlinux/vmlinux.h"
#include <bpf/bpf_helpers.h>

// Need global variable that has one item per CPU
// to ensure that we're always operating thread-safe.
//BPF_PERCPU_ARRAY(command_heap, struct command, 1);

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct command);
} command_heap SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct command_event);
} commandevent_heap SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct connection_event);
} connectionevent_heap SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct file_upload_event);
} fileuploadevent_heap SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct terminal_update_event);
} terminalupdateevent_heap SEC(".maps");

#endif