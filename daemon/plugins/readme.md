# Custom Plug-Ins

SSHLog supports custom plug-ins by adding Python files to the respective plug-in folder.

Two types of custom plug-ins can be added, "filters" and "actions"

See the [configuration documentation](daemon/config_samples/readme.md) for a more detailed discussion about these plug-in types.

## Filters

As an example, we will create a new type of filter that will check if the client IP address is from an private network or a public network address.

It's helpful to review the payload data for each event type.  These are printed out when the daemon is running in debug mode.  However, for convenience, sample data is updated 
from time to time in the daemon/comms/event_types.py file.

From this file, we can see that there are 3 event types that contain TCP information that we can filter on:

    # {'event_type': 'connection_established', 'ptm_pid': 2782281, 'user_id': 1000, 'username': 'mhill', 'pts_pid': 2782323, 'shell_pid': 2782324, 'tty_id': -1, 'start_time': 1677084819930, 'end_time': 0, 'start_timeraw': 851155551084463, 'end_timeraw': 0, 'tcp_info': {'server_ip': '0', 'client_ip': '127.0.0.1', 'server_port': 0, 'client_port': 36636}}
    # {"event_type": "connection_auth_failed", "ptm_pid":3916537,  "user_id":135,"username":"haproxy","pts_pid":-1,"shell_pid":-1,"tty_id":-1,"start_time":1677430550000,"end_time":1677430550000,"start_timeraw":1677430550000,"end_timeraw":1677430550000,"tcp_info":{"server_ip":"0","client_ip":"127.0.0.1","server_port":0,"client_port":0}}
    # {'event_type': 'connection_close', 'ptm_pid': 2782281, 'user_id': 1000, 'username': 'mhill', 'pts_pid': 2782323, 'shell_pid': 2782324, 'tty_id': -1, 'start_time': 1677084819930, 'end_time': 1677084820174, 'start_timeraw': 851155551084463, 'end_timeraw': 851155795227451, 'tcp_info': {'server_ip': '0', 'client_ip': '127.0.0.1', 'server_port': 0, 'client_port': 36636}}

Notice the "tcp_info" section contains a client_ip value

To create a filter, add a new file to /etc/sshlog/plugins/ip_address_filter.py

Add the following content:

    from plugins.common.plugin import FilterPlugin
    from comms.event_types import *
    import ipaddress
    
    
    class is_private_address_filter(FilterPlugin):
    
        def triggers(self):
            return [SSHTRACE_EVENT_ESTABLISHED_CONNECTION, SSHTRACE_EVENT_AUTH_FAILED_CONNECTION, SSHTRACE_EVENT_CLOSE_CONNECTION]
    
        def filter(self, event_data):
            if self.filter_arg == False:
                # Skip the filter, since they mean to disable it
                return True
    
            client_ip = event_data['tcp_info']['client_ip']
            return ipaddress.ip_address(client_ip).is_private


When the daemon reloads, this file will be loaded dynamically and available to use.  Ideally, you would want to include this file in the codebase and recompile the delivarable.  However, you can also drop this file into /etc/sshlog/plugins/ and it will be loaded at runtime.

In your configuration files in /etc/sshlog/conf.d/ you can now reference this in the "filters" section.  

For example create a file named /etc/sshlog/conf.d/private_ips.yaml:


    events:
      - event: log_private_ips
        triggers:
          - connection_established
        filters:
          is_private_address: True
        actions:
          - action: log_activity
            plugin: eventlogfile_action
            log_file_path: /tmp/test.log


Now, the event will only trigger if the client is connecting on a private IP address range such as 10.x.x.x, 172.16-172.31.x.x or 192.168.x.x

After restarting the daemon and logging into the server from a private IP, you should see a log entry created in /tmp/test.log


## Actions


As an example, we will create an action plugin that records the username and IP address to a spreadsheet.

Create the file /etc/sshlog/plugins/csv_action.py:

    from plugins.common.plugin import ActionPlugin
    import csv

    class save_to_csv_action(ActionPlugin):

        def init_action(self, csv_file, include_username=True):
            self.csv_file_path = csv_file
            self.include_username = include_username
            self.logger.info(f"Initialized action {self.name} with csv file {csv_file}")

        def shutdown_action(self):
            pass

        def execute(self, event_data):
            
            # Open the CSV file in append mode
            with open(self.csv_file_path, 'a', newline='') as csvfile:
                writer = csv.writer(csvfile)

                client_ip = event_data['tcp_info']['client_ip']
                username = event_data['username']
                if self.include_username:
                    writer.writerow([client_ip, username])
                else:
                    writer.writerow([client_ip])


Notice the two arguments csv_file, and include_username.  These will automatically be available to your yaml configuration file as parameters.  The csv_file parameter will be required, and because include_username has a default value, it is optional.

We can now add this to our configuration to /etc/sshlog/conf.d/private_ips.yaml as follows:


    events:
      - event: log_private_ips
        triggers:
          - connection_established
        filters:
          is_private_address: True
        actions:
          - action: record_private_ips_to_csv
            plugin: save_to_csv_action
            csv_file: /tmp/test.csv

After restarting the daemon, and performing a login from a private IP address, you should see entries recorded into the /tmp/test.csv file

## Troubleshooting

To restart the agent, use:

    sudo systemctl restart sshlog

Useful information related to agent startup and configuration file parsing can be found in:

    /var/log/sshlog/sshlogd.log


When the agent restarts, it will report whether or not a filter or action is initialized.  For example:

    Initializing filter plugin ignore_existing_logins
    Initializing action plugin send_to_statsd

Any exceptions that happen in your code will also get reported here.

Sometimes it's useful to run the daemon with debug information enabled.  You can stop the agent:

    sudo systemctl restart sshlog

and run the agent interactively in debug mode:

    sudo sshlogd --debug

This will provide additional information as events are triggered