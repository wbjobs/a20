// +build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_SQL_LEN 4096
#define MAX_USER_LEN 128
#define MAX_DB_LEN 128
#define MAX_IP_LEN 48

enum server_command {
    COM_SLEEP = 0,
    COM_QUIT = 1,
    COM_INIT_DB = 2,
    COM_QUERY = 3,
    COM_FIELD_LIST = 4,
    COM_CREATE_DB = 5,
    COM_DROP_DB = 6,
    COM_REFRESH = 7,
    COM_SHUTDOWN = 8,
    COM_STATISTICS = 9,
    COM_PROCESS_INFO = 10,
    COM_CONNECT = 11,
    COM_PROCESS_KILL = 12,
    COM_DEBUG = 13,
    COM_PING = 14,
    COM_TIME = 15,
    COM_DELAYED_INSERT = 16,
    COM_CHANGE_USER = 17,
    COM_BINLOG_DUMP = 18,
    COM_TABLE_DUMP = 19,
    COM_CONNECT_OUT = 20,
    COM_REGISTER_SLAVE = 21,
    COM_STMT_PREPARE = 22,
    COM_STMT_EXECUTE = 23,
    COM_STMT_SEND_LONG_DATA = 24,
    COM_STMT_CLOSE = 25,
    COM_STMT_RESET = 26,
    COM_SET_OPTION = 27,
    COM_STMT_FETCH = 28,
    COM_DAEMON = 29,
    COM_BINLOG_DUMP_GTID = 30,
    COM_RESET_CONNECTION = 31,
};

struct event {
    u32 pid;
    u32 tid;
    u64 start_ns;
    u64 end_ns;
    u64 duration_ns;
    u32 command;
    char user[MAX_USER_LEN];
    char db[MAX_DB_LEN];
    char client_ip[MAX_IP_LEN];
    u16 client_port;
    u32 sql_len;
    char sql[MAX_SQL_LEN];
};

struct start_info {
    u64 start_ns;
    u32 command;
    char user[MAX_USER_LEN];
    char db[MAX_DB_LEN];
    char client_ip[MAX_IP_LEN];
    u16 client_port;
    u32 sql_len;
    char sql[MAX_SQL_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);
    __type(value, struct start_info);
} start_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024 * 1024);
} events SEC(".maps");

static inline int read_sql_from_packet(char *packet, u32 packet_len, char *sql, u32 sql_buf_len, u32 *out_sql_len) {
    if (packet_len < 1) {
        return -1;
    }
    u32 actual_sql_len = packet_len - 1;
    if (actual_sql_len > sql_buf_len - 1) {
        actual_sql_len = sql_buf_len - 1;
    }
    __builtin_memcpy(sql, packet + 1, actual_sql_len);
    sql[actual_sql_len] = '\0';
    *out_sql_len = actual_sql_len;
    return 0;
}

static inline void extract_thd_info(void *thd, struct start_info *info) {
    if (!thd) return;

    void *security_ctx = NULL;
    bpf_probe_read_kernel(&security_ctx, sizeof(security_ctx), thd + 0x8a8);
    if (security_ctx) {
        void *user_ptr = NULL;
        bpf_probe_read_kernel(&user_ptr, sizeof(user_ptr), security_ctx + 0x18);
        if (user_ptr) {
            bpf_probe_read_kernel_str(info->user, MAX_USER_LEN, user_ptr);
        }
        void *db_ptr = NULL;
        bpf_probe_read_kernel(&db_ptr, sizeof(db_ptr), security_ctx + 0x10);
        if (db_ptr) {
            bpf_probe_read_kernel_str(info->db, MAX_DB_LEN, db_ptr);
        }
    }

    void *vio = NULL;
    bpf_probe_read_kernel(&vio, sizeof(vio), thd + 0x4a8);
    if (vio) {
        void *mysql_socket = NULL;
        bpf_probe_read_kernel(&mysql_socket, sizeof(mysql_socket), vio + 0x20);
        if (mysql_socket) {
            bpf_probe_read_kernel_str(info->client_ip, MAX_IP_LEN, mysql_socket + 0x100);
            bpf_probe_read_kernel(&info->client_port, sizeof(info->client_port), mysql_socket + 0x11c);
        }
    }
}

SEC("uprobe/dispatch_command")
int BPF_UPROBE(dispatch_command_entry, void *thd, unsigned int command, char *packet, unsigned int packet_len) {
    u64 tid = bpf_get_current_pid_tgid();
    u32 pid = tid >> 32;
    struct start_info info = {};

    info.start_ns = bpf_ktime_get_ns();
    info.command = command;

    if (command == COM_QUERY || command == COM_STMT_PREPARE || command == COM_STMT_EXECUTE) {
        if (packet && packet_len > 0) {
            read_sql_from_packet(packet, packet_len, info.sql, MAX_SQL_LEN, &info.sql_len);
        }
    }

    extract_thd_info(thd, &info);

    bpf_map_update_elem(&start_map, &tid, &info, BPF_ANY);
    return 0;
}

SEC("uretprobe/dispatch_command")
int BPF_URETPROBE(dispatch_command_exit, int ret) {
    u64 tid = bpf_get_current_pid_tgid();
    u32 pid = tid >> 32;
    u64 now = bpf_ktime_get_ns();

    struct start_info *info = bpf_map_lookup_elem(&start_map, &tid);
    if (!info) {
        return 0;
    }

    struct event *event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!event) {
        bpf_map_delete_elem(&start_map, &tid);
        return 0;
    }

    event->pid = pid;
    event->tid = (u32)tid;
    event->start_ns = info->start_ns;
    event->end_ns = now;
    event->duration_ns = now - info->start_ns;
    event->command = info->command;
    event->client_port = info->client_port;
    event->sql_len = info->sql_len;

    __builtin_memcpy(event->user, info->user, MAX_USER_LEN);
    __builtin_memcpy(event->db, info->db, MAX_DB_LEN);
    __builtin_memcpy(event->client_ip, info->client_ip, MAX_IP_LEN);
    __builtin_memcpy(event->sql, info->sql, MAX_SQL_LEN);

    bpf_ringbuf_submit(event, 0);
    bpf_map_delete_elem(&start_map, &tid);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
