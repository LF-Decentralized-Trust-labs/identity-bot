import Flutter
import UIKit
import Mobilecore

@UIApplicationMain
@objc class AppDelegate: FlutterAppDelegate {
  override func application(
    _ application: UIApplication,
    didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
  ) -> Bool {
    GeneratedPluginRegistrant.register(with: self)

    let controller = window?.rootViewController as! FlutterViewController
    HardwareKeyWrapper.register(messenger: controller.binaryMessenger)
    let channel = FlutterMethodChannel(name: "com.identityagent/mobilecore",
                                       binaryMessenger: controller.binaryMessenger)

    channel.setMethodCallHandler { [weak self] (call, result) in
      switch call.method {
      case "startServer":
        let args = call.arguments as? [String: Any] ?? [:]
        let documentsDir = NSSearchPathForDirectoriesInDomains(.documentDirectory, .userDomainMask, true).first!
        let dataDir = args["dataDir"] as? String ?? "\(documentsDir)/identity_agent_data"
        let port = args["port"] as? Int ?? 8642

        do {
          var error: NSError?
          MobilecoreStartServer(dataDir, Int(port), &error)
          if let error = error {
            result(FlutterError(code: "START_FAILED", message: error.localizedDescription, details: nil))
          } else {
            result(["status": "started", "port": port])
          }
        }

      case "stopServer":
        var error: NSError?
        MobilecoreStopServer(&error)
        if let error = error {
          result(FlutterError(code: "STOP_FAILED", message: error.localizedDescription, details: nil))
        } else {
          result(["status": "stopped"])
        }

      case "isRunning":
        result(MobilecoreIsRunning())

      case "getHealth":
        var error: NSError?
        let health = MobilecoreGetHealth(&error)
        if let error = error {
          result(FlutterError(code: "HEALTH_FAILED", message: error.localizedDescription, details: nil))
        } else {
          result(health)
        }

      case "getPort":
        result(Int(MobilecoreGetPort()))

      case "getDataDir":
        let documentsDir = NSSearchPathForDirectoriesInDomains(.documentDirectory, .userDomainMask, true).first!
        result("\(documentsDir)/identity_agent_data")

      default:
        result(FlutterMethodNotImplemented)
      }
    }

    return super.application(application, didFinishLaunchingWithOptions: launchOptions)
  }
}
