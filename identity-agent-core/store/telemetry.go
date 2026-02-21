package store

type SyscallEvent struct {
        ID          string `json:"id" db:"id"`
        AppID       string `json:"app_id" db:"app_id"`
        Timestamp   string `json:"timestamp" db:"timestamp"`
        PID         int    `json:"pid" db:"pid"`
        TID         int    `json:"tid,omitempty" db:"tid"`
        SyscallNum  int    `json:"syscall_num" db:"syscall_num"`
        SyscallName string `json:"syscall_name" db:"syscall_name"`
        Args        string `json:"args,omitempty" db:"args"`
        ReturnValue int    `json:"return_value" db:"return_value"`
        Comm        string `json:"comm,omitempty" db:"comm"`
        Success     bool   `json:"success" db:"success"`
}

type NetworkEvent struct {
        ID        string `json:"id" db:"id"`
        AppID     string `json:"app_id" db:"app_id"`
        Timestamp string `json:"timestamp" db:"timestamp"`
        Direction string `json:"direction" db:"direction"`
        Protocol  string `json:"protocol" db:"protocol"`
        SrcIP     string `json:"src_ip" db:"src_ip"`
        SrcPort   int    `json:"src_port" db:"src_port"`
        DstIP     string `json:"dst_ip" db:"dst_ip"`
        DstPort   int    `json:"dst_port" db:"dst_port"`
        DNSQuery  string `json:"dns_query,omitempty" db:"dns_query"`
        BytesSent int64  `json:"bytes_sent" db:"bytes_sent"`
        BytesRecv int64  `json:"bytes_recv" db:"bytes_recv"`
        Action    string `json:"action" db:"action"`
}

type FileAccessEvent struct {
        ID        string `json:"id" db:"id"`
        AppID     string `json:"app_id" db:"app_id"`
        Timestamp string `json:"timestamp" db:"timestamp"`
        PID       int    `json:"pid" db:"pid"`
        Path      string `json:"path" db:"path"`
        Operation string `json:"operation" db:"operation"`
        Flags     string `json:"flags,omitempty" db:"flags"`
        Success   bool   `json:"success" db:"success"`
        Comm      string `json:"comm,omitempty" db:"comm"`
}

type TelemetryBatch struct {
        AppID         string            `json:"app_id"`
        Source        string            `json:"source"`
        BatchID       string            `json:"batch_id,omitempty"`
        SyscallEvents []SyscallEvent    `json:"syscall_events,omitempty"`
        NetworkEvents []NetworkEvent    `json:"network_events,omitempty"`
        FileEvents    []FileAccessEvent `json:"file_events,omitempty"`
}

type TelemetrySummary struct {
        AppID              string              `json:"app_id"`
        TotalSyscalls      int                 `json:"total_syscalls"`
        TotalNetworkEvents int                 `json:"total_network_events"`
        TotalFileEvents    int                 `json:"total_file_events"`
        TopSyscalls        []NameCount         `json:"top_syscalls"`
        TopDestinations    []NameCount         `json:"top_destinations"`
        TopFilePaths       []NameCount         `json:"top_file_paths"`
        ProtocolBreakdown  []NameCount         `json:"protocol_breakdown"`
        DirectionBreakdown []NameCount         `json:"direction_breakdown"`
        TimeRange          *TimeRange          `json:"time_range,omitempty"`
}

type NameCount struct {
        Name  string `json:"name"`
        Count int    `json:"count"`
}

type TimeRange struct {
        Start string `json:"start"`
        End   string `json:"end"`
}

type RegoPolicy struct {
        ID          string `json:"id" db:"id"`
        Name        string `json:"name" db:"name"`
        Description string `json:"description" db:"description"`
        Module      string `json:"module" db:"module"`
        Rego        string `json:"rego" db:"rego"`
        CreatedAt   string `json:"created_at" db:"created_at"`
        UpdatedAt   string `json:"updated_at,omitempty" db:"updated_at"`
}
