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
          // This app serves an individual. There is no open-source app for an
          // organization and there is not going to be, so this is settled at
          // build time rather than asked — the screen that used to ask was
          // orphaned when the two apps were split.
          //
          // It decides who may witness and watch for this agent: peers are of
          // the same kind, and an agent that has not been told enrols none.
          var declareError: NSError?
          MobilecoreDeclareEntityType("individual", &declareError)
          if let declareError = declareError {
            NSLog("[mobilecore] could not declare entity type: %@",
                  declareError.localizedDescription)
          }
          // The secret that makes this app, and no other app on the phone,
          // the owner of the core it starts. The Dart side chose it and sends
          // it with every request. Without it nothing on the phone is the
          // owner, so a failure here is reported rather than ignored.
          if let secret = args["localOwnerSecret"] as? String {
            var secretError: NSError?
            MobilecoreDeclareLocalOwnerSecret(secret, &secretError)
            if let secretError = secretError {
              result(FlutterError(code: "START_FAILED", message: secretError.localizedDescription, details: nil))
              return
            }
          }
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
