loglevel = "2"
user = "madcat"
group = "madcat"

-- Netzwerk
hostaddress = "<REPLACE_IP>"
interface = "<REPLACE_IFACE>"
tcp_listening_port = "65535"
tcp_connection_timeout = "5"

-- Legacy Payload-Verzeichnisse
path_to_save_tcp_streams = "/data/tpm/"
path_to_save_udp_data = "/data/upm/"
path_to_save_icmp_data = "/data/ipm/"

bufsize = "16384"
udpproxy_connection_timeout = "5"
proxy_wait_restart = "2"

-- RAW-Modul Filter
raw_pcap_filter_exp = "(not ip6 multicast) and inbound and ip6"

-- TCP Proxy (Beispiel für SSH auf Port 222)
tcpproxy = {
  [222] = { "127.0.0.1", 22 }
}

-- UDP Proxy (Beispiel: Google DNS)
udpproxy_tobackend_addr = "<REPLACE_IP>"
udpproxy = {
  [533] = { "8.8.4.4", 53 },
  [534] = { "8.8.8.8", 53 }
}

-- TCP Postprocessor
con_wait = 10
syn_timeout = 10
syn_wait_proxy = 10

enable_conntrack = 1
ct_status_grace_time = 10
syn_empty_queue = 0
best_guess = 0
best_guess_timeout = 60

header_fifo = "/tmp/header_json.tpm"
connection_fifo = "/tmp/connect_json.tpm"

-- Enrichment Processor
madcatlog_fifo = "/tmp/logs.erm"
dns_server = "resolver1.opendns.com"
extip_dnsname = "myip.opendns.com"
acquire_interval = 300
enr_split_hd_lines = 32
enr_timeout = 5
enr_output_files = {
  "/data/madcat.log"
}
enr_ip_server_backend = "127.0.0.1:10000"
