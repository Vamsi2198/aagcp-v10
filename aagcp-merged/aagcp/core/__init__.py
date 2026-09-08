"""aagcp.core — the governance engine.

Stdlib only, no I/O, deterministic. Everything here is a pure function of
its inputs, which is what makes plan_hash, forecast_hash and report_hash
mean anything. The parts that touch a network or a numeric library live
outside it: aagcp.platform (warehouses), aagcp.core.verifier_adapter (the
only file that knows numpy exists), aagcp.verify, aagcp.store.
"""
VERSION = "0.9.0"
