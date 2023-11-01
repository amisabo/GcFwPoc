/*
See LICENSE folder for this sample’s licensing information.

Abstract:
This file contains the implementation of the NEFilterDataProvider sub-class.
*/

import NetworkExtension
import os.log
import Foundation
import Darwin
//import os

/**
    The FilterDataProvider class handles connections that match the installed rules by prompting
    the user to allow or deny the connections.
 */
class FilterDataProvider: NEFilterDataProvider {
    // MARK: NEFilterDataProvider
    /*
     * The below verboseDebug reason is due to bug (https://developer.apple.com/forums/thread/82736)
     * in old macos versions which prevents from showing messages recorded as os_log(..., type=.debug)
     * TODO: For new versions (>= 11) use new logger API, as in
     * https://developer.apple.com/documentation/os/logging/generating_log_messages_from_your_code
     */
    private let verboseDebug = false
    private var userIdMap: [Data: uid_t] = [:]

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        // Filter all traffic.
        var filterRules = [NEFilterRule]()
        let inboundNetworkRule = NENetworkRule(remoteNetwork: nil,
                                               remotePrefix: 0,
                                               localNetwork: nil,
                                               localPrefix: 0,
                                               protocol: //.any //.UDP, //.any, //Using UDP only for now because installing while in TCP causes traffic to hang and need reconnect.
                                               direction: .any)
        filterRules.append(NEFilterRule(networkRule: inboundNetworkRule, action: .filterData))
        os_log("AMI: Registering rules %{public}@", filterRules)

        // Allow all flows that do not match the filter rules.
        let filterSettings = NEFilterSettings(rules: filterRules, defaultAction: .allow)

        apply(filterSettings) { error in
            if let applyError = error {
                os_log("Failed to apply filter settings: %{public}@", type: .error, applyError.localizedDescription)
            }
            completionHandler(error)
        }
    }
    
    override func stopFilter(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {

        completionHandler()
    }
    
    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        let localPorts: [String] = ["7777", "8888"]

        guard let socketFlow = flow as? NEFilterSocketFlow,
            let remoteEndpoint = socketFlow.remoteEndpoint as? NWHostEndpoint,
            let localEndpoint = socketFlow.localEndpoint as? NWHostEndpoint else {
                return .allow()
        }

        let flowInfo = [
            FlowInfoKey.localPort.rawValue: localEndpoint.port,
            FlowInfoKey.remoteAddress.rawValue: remoteEndpoint.hostname
        ]

        if socketFlow.socketProtocol == IPPROTO_UDP {
            var user_id : UInt32 = 0
            let uid = userId(fromAuditToken: flow.sourceAppAuditToken)
            if let uid_int = uid as UInt32? {
                user_id = uid_int
            }
            let p = getpwuid(user_id)!
            let uname = String(cString: p.pointee.pw_name)
            let proc_info = get_proc_info(fromAuditToken: flow.sourceAppAuditToken)

            os_log("AMI: UDP flow:  %{public}s:%{public}s %d %{public}s:%{public}d [proc: %d (%{public}s) User: %d (%{public}s)]",
                          localEndpoint.hostname, localEndpoint.port,
                          socketFlow.direction == NETrafficDirection.inbound ? "<-" : "->",
                          remoteEndpoint.hostname, remoteEndpoint.port,
                          proc_info.pid ?? -1, proc_info.path ?? "UnKnown path", user_id, uname)
            if verboseDebug {
                os_log("AMI: UDP flow details %{public}@", flow)
            }
        } else {
            return .allow()
        }

        if !localPorts.contains(localEndpoint.port) {
            return .allow()
        }

        os_log("AMI: Asking user about new flow with local endpoint %{public}@, remote endpoint %{public}@",
               localEndpoint, remoteEndpoint)

        // Ask the app to prompt the user
        let prompted = IPCConnection.shared.promptUser(aboutFlow: flowInfo) { allow in
            let userVerdict: NEFilterNewFlowVerdict = allow ? .allow() : .drop()
            self.resumeFlow(flow, with: userVerdict)
        }

        guard prompted else {
            return .allow()
        }

        return .pause()
    }

    func dataToAuditToken(fromAuditToken auditToken: Data?) -> audit_token_t? {
        guard let auditToken = auditToken else {
            return nil
        }

        guard auditToken.count == MemoryLayout<audit_token_t>.size else {
            return nil
        }

        let tokenT: audit_token_t? = auditToken.withUnsafeBytes { buf in
            guard let baseAddress = buf.baseAddress else {
                return nil
            }
            return baseAddress.assumingMemoryBound(to: audit_token_t.self).pointee
        }
        return tokenT
    }

    func userId(fromAuditToken auditToken: Data?) -> uid_t? {
        guard let auditToken = auditToken else {
            return nil
        }

        if let cached = userIdMap[auditToken] {
            return cached
        }

        guard let token = dataToAuditToken(fromAuditToken: auditToken) else {
            return nil
        }

        let userId = audit_token_to_ruid(token)
        userIdMap[auditToken] = userId
        return userId
    }

    func get_proc_info(fromAuditToken auditToken: Data?) -> (pid: pid_t?, path: String?) {
        guard let token = dataToAuditToken(fromAuditToken: auditToken) else {
            return (nil, nil)
        }

        let secFlags = SecCSFlags()
        var code: SecCode? = nil
        var staticCode: SecStaticCode? = nil
        var status = SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributeAudit : auditToken] as CFDictionary, secFlags, &code)
        guard status == errSecSuccess, let code = code else {
            os_log("AMI: SecCodeCopyGuestWithAttributes failed for token %{public}@, status %{public}@",
                   type: .error, auditToken! as NSData, status)
            if let errString = SecCopyErrorMessageString(status, nil) {
                os_log("AMI: SecCodeCopyGuestWithAttributes error %{public}s", type: .error,
                       errString as NSString)
            }
            return (audit_token_to_pid(token), get_proc_info_insecure(auditToken))
        }

        if verboseDebug {
            os_log("AMI: SecCodeCopyGuestWithAttributes Succesfully got guest code object")
        }

        var url: CFURL? = nil
        status = SecCodeCopyStaticCode(code, secFlags, &staticCode)
        guard let staticCode = staticCode else {
            os_log("AMI: SecCodeCopyStaticCode failed for token %{public}@, status %{public}@",
                   type: .error, auditToken! as NSData, status)
            if let errString = SecCopyErrorMessageString(status, nil) {
                os_log("AMI: SecCodeCopyGuestWithAttributes error %{public}s",
                       type: .error, errString as NSString)
            }
            return (audit_token_to_pid(token), get_proc_info_insecure(auditToken))
        }
        if verboseDebug {
            os_log("AMI: SecCodeCopyStaticCode Succesfully got guest static code object")
        }

        status = SecCodeCopyPath(staticCode, secFlags, &url)
        guard let url = url as URL? else {
            os_log("AMI: SecCodeCopyPath failed for token %{public}@, status %{public}@",
                   type: .error, auditToken! as NSData, status)
            if let errString = SecCopyErrorMessageString(status, nil) {
                os_log("AMI: SecCodeCopyPath error %{public}s", type: .error, errString as NSString)
            }
            return (audit_token_to_pid(token), get_proc_info_insecure(auditToken))
        }
        if verboseDebug {
            os_log("AMI: SecCodeCopyPath Succesfully extracted path from url")
        }

//        let path = String(CFURLGetString(url)) // url.absoluteURL.pat
        if verboseDebug {
            os_log("AMI: Succesfully extracted non-nil path from url")
        }
        return (audit_token_to_pid(token), url.path)
    }

    func get_proc_info_insecure(_ auditToken: Data?) -> String? {
    if verboseDebug {
        os_log("AMI: get_proc_info_insecure starting")
    }
    guard let auditToken = auditToken else {
        os_log("AMI: get_proc_info_insecure no audit token - aborting", type: .error)
        return nil
    }
    if auditToken.count == MemoryLayout<audit_token_t>.size {
        let pid = auditToken.withUnsafeBytes { buffer in
            audit_token_to_pid(buffer.baseAddress!.assumingMemoryBound(to: audit_token_t.self).pointee)
        }
        let pathbuf = UnsafeMutablePointer<Int8>.allocate(capacity: Int(PROC_PIDPATHINFO_SIZE))
        defer {
            pathbuf.deallocate()
        }

        /*
         * For the below function to compile need to add libproc.tbd to
         * the extension project's build phases -> Link binaries with libraries 
         * (same as done for libbsm). 
         * affects GcFwPoc.xcodeproj/project.pbxproj
         */
        let ret = proc_pidpath(pid, pathbuf, UInt32(PROC_PIDPATHINFO_SIZE))
        if ret <= 0 {
            os_log("AMI: proc_pidpath error %{public}d", type: .error, ret)
            return nil
        }
        os_log("AMI: proc_pidpath Succesfully extracted path", type: .error)
        return String(cString: pathbuf)
    }
    return nil
}
}
