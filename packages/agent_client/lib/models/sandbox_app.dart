class SandboxApp {
  final String id;
  final String name;
  final String? description;
  final String? version;
  final String executionType;
  final String displayMethod;
  final String networkMode;
  final String installStatus;
  final String? containerImage;
  final int? containerImageSizeBytes;
  final String? binaryPath;
  final String? createdAt;
  final String? updatedAt;

  SandboxApp({
    required this.id,
    required this.name,
    this.description,
    this.version,
    required this.executionType,
    required this.displayMethod,
    required this.networkMode,
    required this.installStatus,
    this.containerImage,
    this.containerImageSizeBytes,
    this.binaryPath,
    this.createdAt,
    this.updatedAt,
  });

  factory SandboxApp.fromJson(Map<String, dynamic> json) {
    return SandboxApp(
      id: json['id'] ?? '',
      name: json['name'] ?? '',
      description: json['description'],
      version: json['version'],
      executionType: json['execution_type'] ?? '',
      displayMethod: json['display_method'] ?? '',
      networkMode: json['network_mode'] ?? '',
      installStatus: json['install_status'] ?? 'available',
      containerImage: json['container_image'],
      containerImageSizeBytes: json['container_image_size_bytes'],
      binaryPath: json['binary_path'],
      createdAt: json['created_at'],
      updatedAt: json['updated_at'],
    );
  }

  bool get isContainer => executionType == 'container';
  bool get isCompiled => executionType == 'compiled';
  bool get isInstalled => installStatus == 'installed';
  bool get isInstalling => installStatus == 'installing';
  bool get isAvailable => installStatus == 'available';

  String get imageSizeDisplay {
    if (containerImageSizeBytes == null || containerImageSizeBytes == 0) {
      return 'Unknown size';
    }
    final mb = containerImageSizeBytes! / (1024 * 1024);
    if (mb > 1024) {
      return '${(mb / 1024).toStringAsFixed(1)} GB';
    }
    return '${mb.toStringAsFixed(0)} MB';
  }

  IconType get iconType {
    switch (id) {
      case 'chromium':
        return IconType.browser;
      case 'openwebui':
        return IconType.ai;
      case 'openclaw':
        return IconType.code;
      case 'go-demo':
        return IconType.terminal;
      default:
        return IconType.app;
    }
  }
}

enum IconType { browser, ai, code, terminal, app }

class SandboxInstance {
  final String id;
  final String appId;
  final String status;
  final int? proxyPort;
  final int? displayPort;
  final int? agentApiPort;

  SandboxInstance({
    required this.id,
    required this.appId,
    required this.status,
    this.proxyPort,
    this.displayPort,
    this.agentApiPort,
  });

  factory SandboxInstance.fromJson(Map<String, dynamic> json) {
    return SandboxInstance(
      id: json['id'] ?? '',
      appId: json['app_id'] ?? '',
      status: json['status'] ?? '',
      proxyPort: json['proxy_port'],
      displayPort: json['display_port'],
      agentApiPort: json['agent_api_port'],
    );
  }

  bool get isRunning => status == 'running' || status == 'starting';
}

class AppStatus {
  final String state;
  final double cpuPercent;
  final int memoryUsedMb;
  final int memoryLimitMb;
  final int diskUsedMb;
  final int diskLimitMb;
  final int networkTxKb;
  final int networkRxKb;

  AppStatus({
    required this.state,
    this.cpuPercent = 0,
    this.memoryUsedMb = 0,
    this.memoryLimitMb = 0,
    this.diskUsedMb = 0,
    this.diskLimitMb = 0,
    this.networkTxKb = 0,
    this.networkRxKb = 0,
  });

  factory AppStatus.fromJson(Map<String, dynamic> json) {
    final status = json['status'] as Map<String, dynamic>? ?? {};
    final stats = json['stats'] as Map<String, dynamic>? ?? {};

    return AppStatus(
      state: status['state'] ?? 'stopped',
      cpuPercent: (stats['cpu_percent'] ?? 0).toDouble(),
      memoryUsedMb: (stats['memory_used_mb'] ?? 0).toInt(),
      memoryLimitMb: (stats['memory_limit_mb'] ?? 0).toInt(),
      diskUsedMb: (stats['disk_used_mb'] ?? 0).toInt(),
      diskLimitMb: (stats['disk_limit_mb'] ?? 0).toInt(),
      networkTxKb: (stats['network_tx_kb'] ?? 0).toInt(),
      networkRxKb: (stats['network_rx_kb'] ?? 0).toInt(),
    );
  }

  bool get isRunning => state == 'running' || state == 'starting';
}
