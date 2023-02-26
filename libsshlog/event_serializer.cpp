#include "event_serializer.h"
#include "bpf/sshtrace_events.h"
#include "event_serializer.h"
#include <arpa/inet.h>
#include <plog/Log.h>
#include <string>
#include <time.h>
#include <yyjson.h>

static const char* get_event_str(int event_type) {
  switch (event_type) {
  case SSHTRACE_EVENT_NEW_CONNECTION:
    return "connection_new";
  case SSHTRACE_EVENT_ESTABLISHED_CONNECTION:
    return "connection_established";
  case SSHTRACE_EVENT_AUTH_FAILED_CONNECTION:
    return "connection_auth_failed";
  case SSHTRACE_EVENT_CLOSE_CONNECTION:
    return "connection_close";
  case SSHTRACE_EVENT_COMMAND_START:
    return "command_start";
  case SSHTRACE_EVENT_COMMAND_END:
    return "command_finish";
  case SSHTRACE_EVENT_FILE_UPLOAD:
    return "file_upload";
  case SSHTRACE_EVENT_TERMINAL_UPDATE:
    return "terminal_update";
  default:
    return "unknown";
  }
}

static int64_t boottime_diff = -1;
static int64_t highest_boottime = -1;
static int64_t compute_boottime_diff_from_realtime(int64_t boottime) {
  // ebpf reports time since bootup (including suspend) see: bpf_ktime_get_boot_ns
  // We need to convert this to wall clock time by comparing the offset

  const int64_t NANOS_IN_A_SEC = 1000000000;
  const int64_t NANOS_IN_A_MILLIS = 1000000;
  const int64_t MILLIS_IN_A_SEC = 1000;
  const int SECONDS_BETWEEN_RECOMPUTE = 10;
  // Subtract the two timespecs and convert to milliseconds
  int64_t sec_diff = (boottime - highest_boottime) / NANOS_IN_A_SEC;
  if (boottime_diff == -1 || sec_diff >= SECONDS_BETWEEN_RECOMPUTE) {
    // Recompute the difference.  Let's do this every 10 seconds or so because
    // the MONOTONIC time does not include suspend time.  So if the machine goes to sleep/wakes up all times will be off
    // until recomputed
    struct timespec ts_bt, ts_rt;
    clock_gettime(CLOCK_MONOTONIC, &ts_bt);
    clock_gettime(CLOCK_REALTIME, &ts_rt);

    boottime_diff =
        (ts_rt.tv_sec - ts_bt.tv_sec) * MILLIS_IN_A_SEC + (ts_rt.tv_nsec - ts_bt.tv_nsec) / NANOS_IN_A_MILLIS;

    PLOG_DEBUG << "Recomputing realtime ms: " << sec_diff << " - " << highest_boottime << " - "
               << ts_rt.tv_sec * MILLIS_IN_A_SEC + (ts_rt.tv_nsec / NANOS_IN_A_MILLIS) << "  Recomputing Boottime sec "
               << ts_bt.tv_sec << " nsec: " << ts_bt.tv_nsec << "  Realtime sec: " << ts_rt.tv_sec
               << " nsec: " << ts_rt.tv_nsec << " -- diff: " << boottime_diff;

    if ((int64_t) boottime > highest_boottime)
      highest_boottime = boottime;
  }

  if (boottime == 0)
    return 0;

  // PLOG_VERBOSE << "boottime " << (boottime / NANOS_IN_A_MILLIS) << " + diff " << boottime_diff << " = "
  //              << (boottime / NANOS_IN_A_MILLIS) + boottime_diff;

  // Boottime (from bpf) will be in nanoseconds.  Convert to ms and add the diff to get to realtime
  return (boottime / NANOS_IN_A_MILLIS) + boottime_diff;
}
static void serialize_connection(const struct connection_event* event, const struct connection* conn,
                                 yyjson_mut_doc* doc, yyjson_mut_val* root) {

  yyjson_mut_obj_add_int(doc, root, "user_id", conn->user_id);
  yyjson_mut_obj_add_str(doc, root, "username", conn->username);

  yyjson_mut_obj_add_int(doc, root, "pts_pid", conn->pts_tgid);
  yyjson_mut_obj_add_int(doc, root, "shell_pid", conn->shell_tgid);
  yyjson_mut_obj_add_int(doc, root, "tty_id", conn->tty_id);

  if (event->event_type == SSHTRACE_EVENT_AUTH_FAILED_CONNECTION) {
    // Auth failures are not created via ebpf, so the timestamps are already in milliseconds.
    // No need to do any extra conversion
    yyjson_mut_obj_add_int(doc, root, "start_time", conn->start_time);
    yyjson_mut_obj_add_int(doc, root, "end_time", conn->end_time);
  } else {
    yyjson_mut_obj_add_int(doc, root, "start_time", compute_boottime_diff_from_realtime(conn->start_time));
    yyjson_mut_obj_add_int(doc, root, "end_time", compute_boottime_diff_from_realtime(conn->end_time));
  }

  yyjson_mut_obj_add_int(doc, root, "start_timeraw", conn->start_time);
  yyjson_mut_obj_add_int(doc, root, "end_timeraw", conn->end_time);

  struct in_addr ip_addr;

  yyjson_mut_val* tcp_info_val = yyjson_mut_obj(doc);
  ip_addr.s_addr = conn->tcp_info.server_ip;
  if (conn->tcp_info.server_ip == 0)
    yyjson_mut_obj_add_str(doc, tcp_info_val, "server_ip", "0");
  else
    yyjson_mut_obj_add_str(doc, tcp_info_val, "server_ip", inet_ntoa(ip_addr));
  ip_addr.s_addr = conn->tcp_info.client_ip;
  if (conn->tcp_info.client_ip == 0)
    yyjson_mut_obj_add_str(doc, tcp_info_val, "client_ip", "0");
  else
    yyjson_mut_obj_add_str(doc, tcp_info_val, "client_ip", inet_ntoa(ip_addr));
  yyjson_mut_obj_add_int(doc, tcp_info_val, "server_port", conn->tcp_info.server_port);
  yyjson_mut_obj_add_int(doc, tcp_info_val, "client_port", conn->tcp_info.client_port);
  yyjson_mut_obj_add_val(doc, root, "tcp_info", tcp_info_val);
}
static void serialize_command(const struct command* cmd, yyjson_mut_doc* doc, yyjson_mut_val* root) {

  yyjson_mut_obj_add_str(doc, root, "filename", cmd->filename);

  yyjson_mut_obj_add_int(doc, root, "start_time", compute_boottime_diff_from_realtime(cmd->start_time));
  yyjson_mut_obj_add_int(doc, root, "end_time", compute_boottime_diff_from_realtime(cmd->end_time));

  yyjson_mut_obj_add_int(doc, root, "exit_code", cmd->exit_code);

  yyjson_mut_obj_add_int(doc, root, "stdout_size", cmd->stdout_offset);
  yyjson_mut_obj_add_str(doc, root, "stdout", cmd->stdout);
  yyjson_mut_obj_add_str(doc, root, "args", cmd->args);

  yyjson_mut_obj_add_int(doc, root, "parent_pid", cmd->parent_tgid);
  yyjson_mut_obj_add_int(doc, root, "pid", cmd->current_tgid);
}

char* serialize_event(void* event_struct) {

  const struct event* e_generic = (const struct event*) event_struct;

  // Create a mutable doc
  yyjson_mut_doc* doc = yyjson_mut_doc_new(NULL);
  yyjson_mut_val* root = yyjson_mut_obj(doc);
  yyjson_mut_doc_set_root(doc, root);

  yyjson_mut_obj_add_str(doc, root, "event_type", get_event_str(e_generic->event_type));

  if (e_generic->event_type == SSHTRACE_EVENT_NEW_CONNECTION ||
      e_generic->event_type == SSHTRACE_EVENT_ESTABLISHED_CONNECTION ||
      e_generic->event_type == SSHTRACE_EVENT_AUTH_FAILED_CONNECTION ||
      e_generic->event_type == SSHTRACE_EVENT_CLOSE_CONNECTION) {

    const struct connection_event* e = (const struct connection_event*) event_struct;
    yyjson_mut_obj_add_int(doc, root, "ptm_pid", e->ptm_pid);
    serialize_connection(e, &e->conn, doc, root);

  } else if (e_generic->event_type == SSHTRACE_EVENT_COMMAND_START ||
             e_generic->event_type == SSHTRACE_EVENT_COMMAND_END) {
    const struct command_event* e = (const struct command_event*) event_struct;
    yyjson_mut_obj_add_int(doc, root, "ptm_pid", e->ptm_pid);
    serialize_command(&e->cmd, doc, root);
  } else if (e_generic->event_type == SSHTRACE_EVENT_TERMINAL_UPDATE) {

    const struct terminal_update_event* e = (const struct terminal_update_event*) event_struct;
    yyjson_mut_obj_add_int(doc, root, "ptm_pid", e->ptm_pid);
    yyjson_mut_obj_add_str(doc, root, "terminal_data", e->aggregated_data.c_str());
    yyjson_mut_obj_add_int(doc, root, "data_len", e->data_len);
  } else if (e_generic->event_type == SSHTRACE_EVENT_FILE_UPLOAD) {

    const struct file_upload_event* e = (const struct file_upload_event*) event_struct;
    char mode_s[8];
    //strmode(e->file_mode, mode_s);
    snprintf(mode_s, sizeof(mode_s), "%3o", e->file_mode & 0777);
    yyjson_mut_obj_add_int(doc, root, "ptm_pid", e->ptm_pid);
    yyjson_mut_obj_add_str(doc, root, "target_path", e->target_path);
    //yyjson_mut_obj_add_int(doc, root, "file_mode", e->file_mode);
    yyjson_mut_obj_add_str(doc, root, "file_mode", mode_s);

  } else {
    PLOG_WARNING << "Unknown event type sent for serialization: " << e_generic->event_type;
  }

  // To string, minified
  char* json = yyjson_mut_write(doc, 0, NULL);

  // Free the doc
  yyjson_mut_doc_free(doc);

  if (json) {
    PLOG_VERBOSE << "serialized: " << json;
  } else {
    PLOG_WARNING << "json: Error generating json content";
  }

  return json;
}