# assess.qs — a runnable example of the shared QYVORA scripting engine driving
# anansi's attack-surface scan.
#
#     anansi script run examples/assess.qs
#
# anansi is a live attack-surface scanner: this example performs real network
# requests against an explicitly safe public target (example.com) and takes
# roughly one to two minutes. Only scan targets you are authorized to test.

# The target to scan.
set scan.target -> "example.com"

# Limit the module set to keep the example quick. Remove this line to run
# anansi's full default module set (discovery, probe, tls, headers, paths,
# tech, takeover, osint, chain, exploit).
set scan.modules -> "discovery,probe,tls,headers"

# Run the scan. The report is captured for $(...) interpolation below.
run anansi.scan

# Read live properties from the completed scan via $(...).
echo -> "target     = $(result.target)"
echo -> "subdomains = $(result.subdomains)"
echo -> "probes     = $(result.probes)"
echo -> "tls        = $(result.tls)"
echo -> "headers    = $(result.headers)"
echo -> "findings   = $(result.findings)"
echo -> "chains     = $(result.chains)"

# Show capability metadata and write a JSON report.
show anansi.scan
report -> "anansi-report.json"

echo -> "done"
