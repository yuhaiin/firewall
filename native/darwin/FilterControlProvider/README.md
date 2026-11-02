# macOS control side

The macOS SDK explicitly marks `NEFilterControlProvider`,
`NEFilterControlVerdict` and `NEFilterDataProvider.handleRulesChanged` unavailable.
They cannot be used in a real macOS target. The signed FirewallHost implements
the control role using app-group snapshots and the system extension's declared,
authenticated Mach control endpoint. Flow decisions remain entirely local to
NEFilterDataProvider. No unavailable API is replaced with a fake success stub.
