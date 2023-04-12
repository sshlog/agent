# sshlog config

The sshlog library provides a set of event-driven actions that can monitor, log, and react to SSH-related activities on a server. Included are a number of sample YAML configuration files to enable different types of logging and event-triggered actions. In this guide, we will describe how to configure the sshlog library with YAML configuration files.

## Config location and loading

The default location for sshlog configuration files is the folder: /etc/sshlog/conf.d/

You may place one or more valid .yaml configuration files in this directory, and the software will load each configuration file in this directory on startup.  

To restart the agent, use:

    sudo systemctl restart sshlog

Useful information related to agent startup and configuration file parsing can be found in:

    /var/log/sshlog/sshlogd.log


## Sample Configuration

	# log_events.yaml
	# Description:
	# Logs all events (e.g., login, command start, file upload) to a single file

	events:
	  - event: log_general_activity
	    triggers:
	      - connection_established
	      - connection_auth_failed
	      - connection_close
	      - command_start
	      - command_finish
	      - file_upload
	    filters:
	      ignore_existing_logins: True
	    actions:
	      - action: log_events
	        plugin: eventlogfile_action
	        log_file_path: /var/log/sshlog/event.log
	        max_size_mb: 10
	        number_of_log_files: 5

### events

The log_events.yaml creates a log file in /var/log/sshlog/event.log that writes a line entry for each triggered event.  

Each config file can contain one or more "events".  This sample configuration only contains one event, named "log_general_activity".  This event name can be anything, it simply must be unique across all configuration files

### triggers

The event will fire based on one or more "triggers".  If a trigger is listed, then this event will activate whenever the configured trigger happens.  The "triggers" are a list that can be any of the following:

  - **connection_established** - When a new SSH connection is successfully made
  - **connection_auth_failed** - When an SSH connection is attempted but fails due to authentication
  - **connection_close** - When an SSH connection is terminated
  - **command_start** - When a user executes a command within the SSH connection
  - **command_finish** - When the command completes
  - **terminal_update** - Whenever the terminal is updated either due to a keypress or the screen updates due to terminal output.  These triggers are extremely numerous.
  - **file_upload** - When a file is transferred to the server via scp


### filters

Filters may or may not be applied.  If no filters are configured, then the event will always activate when a trigger occurs.  A filter is useful for restricting the activation to certain conditions.  For example, you may want the event to activate only when a particular username matches.  You may apply more than one filter.  In that case, all filters must pass in order for the event to activate.

The source code for filters can be found in the plugins/filters/ directory.  Each filter may only apply to a subset of triggers.  For example, the "command_name" filter only applies to command_start and command_finish triggers.

This example is configured to "ignore_existing_logins".  When the sshlog daemon initially starts or is restarted, it will send out "connection_established" for all existing SSH connections.  Applying this filter, means that we only consider true new connections, rather than simply cases when the agent restarts.

There are a number of possible filters you can enable:

  - **command_name** - The executed command must match the name exactly (e.g., sudo)
  - **command_name_regex** - The executed command must match the regex
  - **command_exit_code** - The command's exit code must match.  This supports comparisons (e.g., 0, != 0, > 1, etc).
  - **command_output_contains** - Evaluates the first 2,048 bytes of command output and looks for matching characters
  - **command_output_contains_regex** - Evaluates the first 2,048 bytes of command output and looks for matching characters via regex
  - **username** - The logged in username matches this string (e.g., jdoe)
  - **username_regex** - The logged in username matches this regex
  - **require_tty** - Whether a TTY session is required to match.  Some sessions (e.g., single command execution or scp) do not create a TTY
  - **ignore_existing_logins** - Only consider true new connections, rather than simply triggers that are sent when the agent restarts
  - **upload_file_path** - A file SCP must match this full destination path
  - **upload_file_path_regex** - A file SCP must match this destination path regex

### actions

If the event activates, then the action defines what steps are taken next.  For example, it could write to a log file, send an e-mail, or POST via WebHook.

The action name can be anything, it simply must be unique across all configured files.  The "plugin" value must match the name of an available action plugin.  The rest of the parameters are specific to each action.

Actions are defined in the plugins/actions/ folder.  The required and options parameters are enumerated in the "init_action" function.

Below is a list of possible actions:

  - **webhook_action** - Send an HTTP POST or GET to a specified URL endpoint
     - Parameters: webhook_url, do_get_request=False

  - **statsd_action** - Send statsd metric data via UDP to the specified server and port
     - Parameters: server_address, port=8125, statsd_prefix='sshlog'

  - **slack_action** - Post a Slack message to a configured Slack app/webhook URL
     - Parameters: slack_webhook_url

  - **sessionlog_action** - Record all terminal activity to a log file
     - Parameters: log_directory, timestamp_frequency_seconds=-1)

  - **runcommand_action** - Run the specified executable
     - Parameters: command, args=[], timeout=None

  - **eventlogfile_action** - Record event activity to a log file
     - Parameters: log_file_path, output_json=False, max_size_mb=20, number_of_log_files=2

  - **email_action** - Send an e-mail using the specified SMTP server
     - Parameters: sender, recipient, subject, body, smtp_server, smtp_port, username=None, password=None

 - **syslog_action** - Post event data to a remote syslog server
     - Parameters: server_address, port=514, program_name='sshlog', udp=True, output_json=False, facility=pysyslogclient.FAC_SYSTEM, severity=pysyslogclient.SEV_INFO
