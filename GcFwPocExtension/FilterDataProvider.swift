/*
See LICENSE folder for this sample’s licensing information.

Abstract:
This file contains the implementation of the NEFilterDataProvider sub-class.
*/

import NetworkExtension
import os.log

/**
    The FilterDataProvider class handles connections that match the installed rules by prompting
    the user to allow or deny the connections.
 */
class FilterDataProvider: NEFilterDataProvider {

    // MARK: Properties

    // The TCP port which the filter is interested in.
    var localPorts: [String] = ["7777", "8888", "9999"]

    // MARK: NEFilterDataProvider

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        // Filter incoming TCP connections on port 8888
        var filterRules = [NEFilterRule]()
        for localPort in localPorts {
            filterRules += ["0.0.0.0", "::"].map { address ->   NEFilterRule in
            let localNetwork = NWHostEndpoint(hostname: address, port: localPort)
            let inboundNetworkRule = NENetworkRule(remoteNetwork: nil,
                                                   remotePrefix: 0,
                                                   localNetwork: localNetwork,
                                                   localPrefix: 0,
                                                   protocol: .TCP,
                                                   direction: .inbound)
            return NEFilterRule(networkRule: inboundNetworkRule, action: .filterData)
            }
            os_log("AMI: after adding of port %{public}s len is %d", localPort, filterRules.count)
        }
        
        os_log("AMI: registered rules!")
        os_log("AMI: the rules are %{public}@", filterRules)

        // Allow all flows that do not match the filter rules.
        let filterSettings = NEFilterSettings(rules: filterRules, defaultAction: .allow)

        apply(filterSettings) { error in
            if let applyError = error {
                os_log("Failed to apply filter settings: %@", applyError.localizedDescription)
            }
            completionHandler(error)
        }
    }
    
    override func stopFilter(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {

        completionHandler()
    }
    
    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {

        guard let socketFlow = flow as? NEFilterSocketFlow,
            let remoteEndpoint = socketFlow.remoteEndpoint as? NWHostEndpoint,
            let localEndpoint = socketFlow.localEndpoint as? NWHostEndpoint else {
                return .allow()
        }

        os_log("AMI: Got a new flow with local endpoint %{public}@, remote endpoint %{public}@", localEndpoint, remoteEndpoint)

        let flowInfo = [
            FlowInfoKey.localPort.rawValue: localEndpoint.port,
            FlowInfoKey.remoteAddress.rawValue: remoteEndpoint.hostname
        ]

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
}
