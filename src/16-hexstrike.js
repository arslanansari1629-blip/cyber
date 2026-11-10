/* AEGIS // SENTINEL v2.1 — HexStrike AI compatibility layer.
 *
 * Upstream: https://github.com/0x4m4/hexstrike-ai (MIT, v6.0, 151 MCP tools,
 * 12+ autonomous agents). We vendor the *catalog and the MCP-shaped contract*,
 * not the server, not the binaries and not the offensive behaviour.
 *
 * Every upstream tool name is classified into exactly one of three modes:
 *   adapter     — mapped to a real, offline AEGIS analysis engine
 *   blocked     — mapped to a hard-refused AEGIS capability class
 *   unavailable — requires the upstream Flask/FastMCP server or external
 *                 binaries; never executed in this build
 *
 * Nothing here opens a socket, spawns a process or touches a filesystem.
 */
(function (root) {
  'use strict';
  var isNode = typeof module !== 'undefined' && module.exports;
  var DATA = isNode ? require('./00-data.js') : root.AEGIS_DATA;
  var D2 = isNode ? require('./05-data2.js') : root.AEGIS_DATA2;
  var E = isNode ? require('./10-engine.js') : root.AEGIS_ENGINE;
  var A = isNode ? require('./15-advanced.js') : root.AEGIS_ADVANCED;

  var UPSTREAM = {
    repo: '0x4m4/hexstrike-ai',
    url: 'https://github.com/0x4m4/hexstrike-ai',
    version: '6.0.0',
    license: 'MIT',
    mcpConfig: 'hexstrike-ai-mcp.json',
    server: 'hexstrike_server.py (Flask, /api/*)',
    bridge: 'hexstrike_mcp.py (FastMCP, python3 --server http://IP:8888)',
    decoratedTools: 151,
    note: 'Catalog-only integration. No upstream code is bundled or executed.'
  };

  /* 12 specialised agents described in the upstream README. In AEGIS they are
   * planning personas, not autonomous executors. */
  var AGENTS = [
    { id: 'BugBountyAgent', role: 'Reconnaissance workflow planning', status: 'adapter', caps: ['govern.report', 'intel.ioc'] },
    { id: 'CTFSolverAgent', role: 'Binary / forensics challenge analysis', status: 'blocked', caps: ['exploit.execute'] },
    { id: 'CVEIntelligenceManager', role: 'Vulnerability intelligence', status: 'adapter', caps: ['config.sbom', 'govern.report'] },
    { id: 'AIExploitGenerator', role: 'Automated exploit development', status: 'blocked', caps: ['exploit.execute'] },
    { id: 'IntelligentDecisionEngine', role: 'Tool selection & parameter optimisation', status: 'adapter', caps: ['govern.report'] },
    { id: 'VulnerabilityIntelligenceAgent', role: 'Correlate findings into risk', status: 'adapter', caps: ['govern.report', 'telemetry.correlate'] },
    { id: 'AttackChainDiscoveryAgent', role: 'Multi-stage chain reconstruction', status: 'adapter', caps: ['telemetry.correlate'] },
    { id: 'ThreatHuntingAssistant', role: 'Hunt hypotheses over telemetry', status: 'adapter', caps: ['telemetry.detect', 'telemetry.anomaly'] },
    { id: 'CloudSecurityAgent', role: 'IAM / K8s posture review', status: 'adapter', caps: ['config.iam', 'config.k8s'] },
    { id: 'WebAppSecurityAgent', role: 'HTTP hardening & dependency review', status: 'adapter', caps: ['config.hardening', 'config.sbom'] },
    { id: 'OSINTAgent', role: 'Passive indicator correlation', status: 'adapter', caps: ['intel.ioc'] },
    { id: 'RedTeamOperator', role: 'Offensive engagement execution', status: 'blocked', caps: ['net.scan', 'exploit.execute', 'credential.attack'] }
  ];

  /* Exact tool names from @mcp.tool() decorators in hexstrike_mcp.py.
   * 151 decorated functions, 150 unique names (httpx_probe is declared twice). */
  var RAW_TOOLS = 'nmap_scan,gobuster_scan,nuclei_scan,prowler_scan,trivy_scan,scout_suite_assessment,cloudmapper_analysis,pacu_exploitation,kube_hunter_scan,kube_bench_cis,docker_bench_security_scan,clair_vulnerability_scan,falco_runtime_monitoring,checkov_iac_scan,terrascan_iac_scan,create_file,modify_file,delete_file,list_files,generate_payload,install_python_package,execute_python_script,dirb_scan,nikto_scan,sqlmap_scan,metasploit_run,hydra_attack,john_crack,wpscan_analyze,enum4linux_scan,ffuf_scan,netexec_scan,amass_scan,hashcat_crack,subfinder_scan,smbmap_scan,rustscan_fast_scan,masscan_high_speed,nmap_advanced_scan,autorecon_comprehensive,enum4linux_ng_advanced,rpcclient_enumeration,nbtscan_netbios,arp_scan_discovery,responder_credential_harvest,volatility_analyze,msfvenom_generate,gdb_analyze,radare2_analyze,binwalk_analyze,ropgadget_search,checksec_analyze,xxd_hexdump,strings_extract,objdump_analyze,ghidra_analysis,pwntools_exploit,one_gadget_search,libc_database_lookup,gdb_peda_debug,angr_symbolic_execution,ropper_gadget_search,pwninit_setup,feroxbuster_scan,dotdotpwn_scan,xsser_scan,wfuzz_scan,dirsearch_scan,katana_crawl,gau_discovery,waybackurls_discovery,arjun_parameter_discovery,paramspider_mining,x8_parameter_discovery,jaeles_vulnerability_scan,dalfox_xss_scan,httpx_probe,anew_data_processing,qsreplace_parameter_replacement,uro_url_filtering,ai_generate_payload,ai_test_payload,ai_generate_attack_suite,api_fuzzer,graphql_scanner,jwt_analyzer,api_schema_analyzer,comprehensive_api_audit,volatility3_analyze,foremost_carving,steghide_analysis,exiftool_extract,hashpump_attack,hakrawler_crawl,paramspider_discovery,burpsuite_scan,zap_scan,arjun_scan,wafw00f_scan,fierce_scan,dnsenum_scan,autorecon_scan,server_health,get_cache_stats,clear_cache,get_telemetry,list_active_processes,get_process_status,terminate_process,pause_process,resume_process,get_process_dashboard,execute_command,monitor_cve_feeds,generate_exploit_from_cve,discover_attack_chains,research_zero_day_opportunities,correlate_threat_intelligence,advanced_payload_generation,vulnerability_intelligence_dashboard,threat_hunting_assistant,get_live_dashboard,create_vulnerability_report,format_tool_output_visual,create_scan_summary,display_system_metrics,analyze_target_intelligence,select_optimal_tools_ai,optimize_tool_parameters_ai,create_attack_chain_ai,intelligent_smart_scan,detect_technologies_ai,ai_reconnaissance_workflow,ai_vulnerability_assessment,bugbounty_reconnaissance_workflow,bugbounty_vulnerability_hunting,bugbounty_business_logic_testing,bugbounty_osint_gathering,bugbounty_file_upload_testing,bugbounty_comprehensive_assessment,bugbounty_authentication_bypass_testing,http_framework_test,browser_agent_inspect,http_set_rules,http_set_scope,http_repeater,http_intruder,burpsuite_alternative_scan,error_handling_statistics,test_error_recovery';

  /* Offline adapter map: upstream tool → real AEGIS engine + capability. */
  var ADAPTERS = {
    server_health: { cap: 'scope.verify', engine: 'chainStatus', label: 'Platform health', kind: 'status' },
    get_live_dashboard: { cap: 'govern.report', engine: 'status', label: 'Live posture dashboard', kind: 'status' },
    display_system_metrics: { cap: 'telemetry.anomaly', engine: 'anomalyDetect', label: 'Event-rate statistics', kind: 'anomaly' },
    analyze_target_intelligence: { cap: 'intel.ioc', engine: 'extractIOCs', label: 'Target indicator extraction', kind: 'ioc' },
    correlate_threat_intelligence: { cap: 'intel.ioc', engine: 'extractIOCs', label: 'Threat-intel correlation', kind: 'ioc' },
    exiftool_extract: { cap: 'intel.ioc', engine: 'extractIOCs', label: 'Metadata / IOC extraction', kind: 'ioc' },
    monitor_cve_feeds: { cap: 'config.sbom', engine: 'analyzeDependencies', label: 'Offline advisory baseline', kind: 'deps' },
    trivy_scan: { cap: 'config.sbom', engine: 'analyzeDependencies', label: 'Container dependency scan', kind: 'deps' },
    clair_vulnerability_scan: { cap: 'config.sbom', engine: 'analyzeDependencies', label: 'Image layer advisory check', kind: 'deps' },
    checksec_analyze: { cap: 'config.sbom', engine: 'analyzeDependencies', label: 'Binary hardening baseline', kind: 'deps' },
    prowler_scan: { cap: 'config.iam', engine: 'analyzeIamPolicy', label: 'Cloud IAM posture', kind: 'iam' },
    scout_suite_assessment: { cap: 'config.iam', engine: 'analyzeIamPolicy', label: 'Multi-cloud policy review', kind: 'iam' },
    cloudmapper_analysis: { cap: 'config.iam', engine: 'analyzeIamPolicy', label: 'Account policy review', kind: 'iam' },
    kube_bench_cis: { cap: 'config.k8s', engine: 'analyzeK8s', label: 'CIS Kubernetes benchmark', kind: 'k8s' },
    kube_hunter_scan: { cap: 'config.k8s', engine: 'analyzeK8s', label: 'Cluster manifest review', kind: 'k8s' },
    docker_bench_security_scan: { cap: 'config.k8s', engine: 'analyzeK8s', label: 'Container runtime posture', kind: 'k8s' },
    falco_runtime_monitoring: { cap: 'telemetry.detect', engine: 'detectLogs', label: 'Runtime rule matches', kind: 'logs' },
    threat_hunting_assistant: { cap: 'telemetry.detect', engine: 'detectLogs', label: 'Hunt over supplied telemetry', kind: 'logs' },
    nuclei_scan: { cap: 'config.hardening', engine: 'analyzeHeaders', label: 'Template-style header checks', kind: 'headers' },
    nikto_scan: { cap: 'config.hardening', engine: 'analyzeHeaders', label: 'Web server hardening', kind: 'headers' },
    wafw00f_scan: { cap: 'config.hardening', engine: 'analyzeHeaders', label: 'Response-header fingerprint', kind: 'headers' },
    checkov_iac_scan: { cap: 'config.secrets', engine: 'secretScan', label: 'IaC secret scan', kind: 'secrets' },
    terrascan_iac_scan: { cap: 'config.secrets', engine: 'secretScan', label: 'IaC secret scan', kind: 'secrets' },
    jwt_analyzer: { cap: 'config.secrets', engine: 'secretScan', label: 'Token material scan', kind: 'secrets' },
    strings_extract: { cap: 'config.secrets', engine: 'secretScan', label: 'String / credential scan', kind: 'secrets' },
    xxd_hexdump: { cap: 'config.secrets', engine: 'secretScan', label: 'Hex / credential scan', kind: 'secrets' },
    anew_data_processing: { cap: 'telemetry.normalize', engine: 'normalizeLogs', label: 'Line dedupe & normalization', kind: 'ingest' },
    uro_url_filtering: { cap: 'telemetry.normalize', engine: 'normalizeLogs', label: 'URL log normalization', kind: 'ingest' },
    qsreplace_parameter_replacement: { cap: 'telemetry.normalize', engine: 'normalizeLogs', label: 'Parameter log normalization', kind: 'ingest' },
    discover_attack_chains: { cap: 'telemetry.correlate', engine: 'attackChains', label: 'Attack-chain reconstruction', kind: 'chains' },
    create_attack_chain_ai: { cap: 'telemetry.correlate', engine: 'attackChains', label: 'Attack-chain reconstruction', kind: 'chains' },
    vulnerability_intelligence_dashboard: { cap: 'govern.report', engine: 'mitreCoverage', label: 'ATT&CK coverage model', kind: 'coverage' },
    select_optimal_tools_ai: { cap: 'govern.report', engine: 'plan', label: 'Capability plan selection', kind: 'plan' },
    optimize_tool_parameters_ai: { cap: 'govern.report', engine: 'plan', label: 'Capability plan refinement', kind: 'plan' },
    create_vulnerability_report: { cap: 'govern.report', engine: 'report', label: 'Evidence report assembly', kind: 'report' }
  };

  /* Hard refusals. Each upstream tool class is bound to an AEGIS blocked
   * capability, so the refusal reason comes from the signed manifest. */
  var UNAVAILABLE_RE = /^(get_cache_stats|get_telemetry|get_process_status|get_process_dashboard|list_active_processes|format_tool_output_visual|create_scan_summary|error_handling_statistics|test_error_recovery|detect_technologies_ai|api_schema_analyzer)/;
  var BLOCK_RULES = [
    { re: /^(execute_command|execute_python_script|install_python_package|create_file|modify_file|delete_file|list_files|generate_payload|generate_exploit_from_cve|ai_generate_payload|ai_test_payload|ai_generate_attack_suite|advanced_payload_generation|msfvenom_generate|pwntools_exploit|angr_symbolic_execution|gdb_|radare2_|binwalk_|ropgadget_|ropper_|one_gadget_|libc_database_|pwninit_|ghidra_|objdump_|volatility|foremost_|steghide_|hashpump_)/, cap: 'exploit.execute', risk: 'code-execution', reason: 'Arbitrary execution, payload generation or host-side binary tooling is outside the passive-analysis manifest.' },
    { re: /^(hydra_|john_crack|hashcat_crack|responder_|netexec_|smbmap_|rpcclient_|enum4linux|metasploit_|pacu_|bugbounty_authentication_bypass|http_intruder|http_repeater|http_set_rules|http_set_scope|http_framework_test|browser_agent_inspect)/, cap: 'credential.attack', risk: 'credential-attack', reason: 'Credential attacks, session manipulation and authentication bypass are prohibited.' },
    { re: /^(terminate_process|pause_process|resume_process|clear_cache)/, cap: 'contain.execute', risk: 'process-control', reason: 'External process control requires a human-approved change through your own infrastructure tooling.' },
    { re: /^(nmap|masscan|rustscan|arp_scan|nbtscan|amass|subfinder|fierce|dnsenum|autorecon|httpx|gobuster|dirb|dirsearch|ffuf|feroxbuster|wfuzz|dotdotpwn|xsser|sqlmap|wpscan|katana|gau_|waybackurls|hakrawler|arjun|paramspider|x8_|jaeles|dalfox|burpsuite|zap_scan|api_fuzzer|graphql_scanner|comprehensive_api_audit|intelligent_smart_scan|ai_reconnaissance_workflow|ai_vulnerability_assessment|bugbounty_|research_zero_day)/, cap: 'net.scan', risk: 'active-probing', reason: 'Active scanning, crawling, fuzzing or exploitation of a target requires a separate authorised engagement.' }
  ];

  var CATEGORY_RULES = [
    ['cloud', /^(prowler|trivy|scout|cloudmapper|pacu|kube|docker|clair|falco|checkov|terrascan|nuclei)/],
    ['binary', /^(volatility|foremost|steghide|exiftool|hashpump|gdb|radare2|binwalk|ropgadget|checksec|xxd|strings|objdump|ghidra|pwntools|one_gadget|libc_database|angr|ropper|pwninit|msfvenom|metasploit)/],
    ['api', /^(api_|graphql|jwt|http_|browser_agent|burpsuite|zap_)/],
    ['osint', /^(amass|subfinder|gau|waybackurls|hakrawler|fierce|dnsenum|theharvester)/],
    ['network', /^(nmap|masscan|rustscan|arp|nbtscan|enum4linux|smbmap|rpcclient|responder|netexec|autorecon|httpx|wafw00f)/],
    ['web', /^(gobuster|dirb|dirsearch|ffuf|feroxbuster|wfuzz|dotdotpwn|xsser|sqlmap|wpscan|katana|arjun|paramspider|x8|jaeles|dalfox|anew|qsreplace|uro|nikto)/],
    ['intelligence', /^(server_health|get_|list_|terminate_|pause_|resume_|clear_cache|execute_|monitor_|generate_|discover_|research_|correlate_|advanced_|vulnerability_|threat_|create_|format_|display_|analyze_|select_|optimize_|intelligent_|detect_|ai_|bugbounty_|error_|test_)/],
    ['utility', /^(create_file|modify_file|delete_file|list_files|install_python)/]
  ];

  function categoryOf(id) {
    for (var i = 0; i < CATEGORY_RULES.length; i++) if (CATEGORY_RULES[i][1].test(id)) return CATEGORY_RULES[i][0];
    return 'utility';
  }
  function uniq(a) { var seen = Object.create(null), out = []; a.forEach(function (x) { if (!seen[x]) { seen[x] = 1; out.push(x); } }); return out; }

  var TOOLS = uniq(RAW_TOOLS.split(',').map(function (x) { return x.trim(); }).filter(Boolean)).map(function (id) {
    var a = ADAPTERS[id] || null;
    var rec = {
      id: id, name: id.replace(/_/g, ' '), category: categoryOf(id),
      mode: a ? 'adapter' : 'unavailable', cap: a ? a.cap : null,
      risk: a ? 'local-analysis' : 'external-backend',
      adapter: a, reason: a ? 'Mapped to a local offline AEGIS analysis engine.' : 'Requires the upstream HexStrike Flask/FastMCP server or external binaries; not bundled.'
    };
    if (!a) {
      if (UNAVAILABLE_RE.test(id)) {
        rec.mode = 'unavailable'; rec.risk = 'external-backend';
        rec.reason = 'Reads or renders upstream HexStrike server runtime state; no server is bundled in this offline build.';
      } else {
        for (var i = 0; i < BLOCK_RULES.length; i++) {
          if (BLOCK_RULES[i].re.test(id)) {
            rec.mode = 'blocked'; rec.cap = BLOCK_RULES[i].cap; rec.risk = BLOCK_RULES[i].risk;
            rec.reason = BLOCK_RULES[i].reason; break;
          }
        }
      }
    }
    return rec;
  });
  var BY_ID = Object.create(null);
  TOOLS.forEach(function (t) { BY_ID[t.id] = t; });

  /* --------------------------- MCP-shaped contract ----------------------- */
  var MCP = {
    name: 'aegis-sentinel-hexstrike-adapter',
    version: '2.1.0',
    upstream: UPSTREAM.repo + '@' + UPSTREAM.version,
    transport: 'in-browser / offline (no stdio, no HTTP, no subprocess)',
    alwaysAllow: [],
    capabilities: { tools: true, resources: true, prompts: true, sampling: false, logging: false },
    tools: TOOLS.map(function (t) {
      return {
        name: t.id, description: t.reason, category: t.category,
        mode: t.mode, capability: t.cap,
        inputSchema: { type: 'object', properties: { target: { type: 'string', description: 'Authorised asset identifier' }, data: { type: 'string', description: 'Operator-supplied text (offline only)' } }, additionalProperties: false }
      };
    }),
    resources: [
      { uri: 'aegis://capabilities', description: 'Signed capability manifest' },
      { uri: 'aegis://scope', description: 'Authorisation records (local state)' },
      { uri: 'aegis://ledger', description: 'SHA-256 hash-chained audit ledger' },
      { uri: 'aegis://attck', description: 'MITRE ATT&CK coverage matrix' }
    ],
    prompts: [
      { name: 'assess-posture', description: 'Plan an offline posture assessment for an authorised asset' },
      { name: 'explain-refusal', description: 'Explain why a capability was refused' },
      { name: 'summarise-evidence', description: 'Summarise local findings into an evidence report' }
    ]
  };

  /* ------------------------------ policy --------------------------------- */
  function summary() {
    var c = { adapter: 0, blocked: 0, unavailable: 0 };
    TOOLS.forEach(function (t) { c[t.mode]++; });
    return {
      upstream: UPSTREAM, total: TOOLS.length, decorated: UPSTREAM.decoratedTools,
      adapters: c.adapter, blocked: c.blocked, unavailable: c.unavailable,
      agents: AGENTS.length, blockedAgents: AGENTS.filter(function (a) { return a.status === 'blocked'; }).length,
      categories: uniq(TOOLS.map(function (t) { return t.category; })).sort()
    };
  }
  function get(id) { return BY_ID[String(id || '').trim()] || null; }
  function tools(filter) {
    var f = String(filter || '').trim().toLowerCase();
    if (!f) return TOOLS.slice();
    if (f === 'adapter' || f === 'blocked' || f === 'unavailable') return TOOLS.filter(function (t) { return t.mode === f; });
    return TOOLS.filter(function (t) {
      return t.id.indexOf(f) !== -1 || t.category === f || (t.cap || '').indexOf(f) !== -1 || t.mode === f;
    });
  }
  function evaluate(id, state, target) {
    var t = get(id);
    if (!t) return { allowed: false, code: 'UNKNOWN_TOOL', reason: 'No HexStrike tool named "' + id + '" in the adapter catalog.', tool: null };
    if (t.mode === 'unavailable') return { allowed: false, code: 'TOOL_UNAVAILABLE', reason: t.reason, tool: t };
    if (t.mode === 'blocked') {
      var gate = A.evaluateCapability(t.cap, state, target || null);
      return { allowed: false, code: 'CAPABILITY_BLOCKED', reason: gate.reason, tool: t, mappedCapability: t.cap, riskClass: t.risk };
    }
    var g = A.evaluateCapability(t.cap, state, target || null);
    return { allowed: g.allowed, code: g.allowed ? 'CAPABILITY_GRANTED' : g.code, reason: g.reason, tool: t, mappedCapability: t.cap };
  }

  /* Deterministic planner. Never invents a capability; only selects from the
   * signed manifest and marks everything else REFUSED. */
  var PLAN_RULES = [
    { re: /(header|csp|harden|web|tls|cookie)/i, steps: ['nuclei_scan', 'nikto_scan', 'wafw00f_scan'] },
    { re: /(iam|policy|cloud|aws|s3|role)/i, steps: ['prowler_scan', 'scout_suite_assessment', 'cloudmapper_analysis'] },
    { re: /(k8s|kube|cluster|pod|container)/i, steps: ['kube_bench_cis', 'kube_hunter_scan', 'docker_bench_security_scan'] },
    { re: /(secret|credential|token|key|iac|terraform)/i, steps: ['checkov_iac_scan', 'terrascan_iac_scan', 'jwt_analyzer'] },
    { re: /(dependency|sbom|cve|package|supply)/i, steps: ['trivy_scan', 'monitor_cve_feeds', 'clair_vulnerability_scan'] },
    { re: /(log|telemetry|siem|detect|hunt|attack chain)/i, steps: ['threat_hunting_assistant', 'anew_data_processing', 'discover_attack_chains'] },
    { re: /(intel|ioc|indicator|phish)/i, steps: ['analyze_target_intelligence', 'correlate_threat_intelligence', 'exiftool_extract'] }
  ];
  function plan(goal) {
    var q = String(goal || '').trim();
    var picked = [];
    PLAN_RULES.forEach(function (r) { if (r.re.test(q)) picked = picked.concat(r.steps); });
    if (!picked.length) picked = ['server_health', 'analyze_target_intelligence', 'discover_attack_chains', 'select_optimal_tools_ai', 'create_vulnerability_report'];
    picked = uniq(picked.concat(['server_health', 'create_vulnerability_report']));
    return {
      goal: q || 'general posture assessment',
      engine: 'deterministic keyword planner (no model call)',
      steps: picked.map(function (id, i) {
        var t = get(id);
        return { order: i + 1, tool: id, mode: t.mode, capability: t.cap, category: t.category,
          decision: t.mode === 'adapter' ? 'ELIGIBLE' : 'REFUSED', reason: t.reason };
      })
    };
  }

  /* Execute an adapter tool against operator-supplied text (or the labelled
   * offline samples). Returns a JSON-RPC-shaped envelope. Pure: no state writes. */
  function call(id, args, state) {
    args = args || {};
    var gate = evaluate(id, state, args.target || null);
    var base = { jsonrpc: '2.0', id: args.id || 1, tool: String(id) };
    if (!gate.allowed) {
      return Object.assign(base, { error: { code: gate.code === 'TOOL_UNAVAILABLE' ? -32002 : -32001,
        message: gate.code, data: { reason: gate.reason, capability: gate.mappedCapability || null, mode: gate.tool ? gate.tool.mode : null } } });
    }
    var t = gate.tool, a = t.adapter, data = args.data || '', out = null, summaryText = '';
    function sample(kind) {
      var S = D2.SAMPLES, map = {
        deps: S.deps, iam: S.iam, k8s: S.k8s, secrets: S.secrets, headers: DATA.SAMPLE_HEADERS,
        logs: DATA.SAMPLE_LOGS, ioc: DATA.SAMPLE_INTEL, ingest: S.jsonl, email: S.email
      };
      return data || map[kind] || S.jsonl;
    }
    switch (a.kind) {
      case 'status':
        out = { assets: E.activeAssets(state).length, findings: (state.findings || []).length,
          alerts: (state.alerts || []).length, ledger: E.verifyChain(state.audit || []) };
        summaryText = 'Ledger ' + (out.ledger.valid ? 'VALID' : 'INVALID') + ' · ' + out.assets + ' assets in scope.';
        break;
      case 'anomaly': { var r = A.anomalyDetect([10, 11, 9, 10, 12, 9, 11, 10, 80, 10]);
        out = { mean: r.mean, upper: r.upper, outliers: r.outliers.length }; summaryText = r.outliers.length + ' statistical outlier(s) in the sample series.'; break; }
      case 'ioc': { var iocs = E.extractIOCs(sample('ioc'));
        out = { total: iocs.length, byType: iocs.reduce(function (o, x) { o[x.type] = (o[x.type] || 0) + 1; return o; }, {}),
          defangedSample: iocs.slice(0, 3).map(function (x) { return x.defanged; }) };
        summaryText = iocs.length + ' indicator(s) extracted and defanged locally; no external lookup performed.'; break; }
      case 'deps': { var d = A.analyzeDependencies(sample('deps'));
        out = { format: d.format, packages: d.packages.length, findings: d.findings.length, score: d.score };
        summaryText = d.findings.length + ' advisory match(es) across ' + d.packages.length + ' packages.'; break; }
      case 'iam': { var iam = A.analyzeIamPolicy(sample('iam'));
        out = { statements: iam.statements, checks: iam.checks.length, fails: iam.checks.filter(function (c) { return c.status === 'fail'; }).length, score: iam.score };
        summaryText = iam.checks.filter(function (c) { return c.status === 'fail'; }).length + ' failing IAM control(s).'; break; }
      case 'k8s': { var k = A.analyzeK8s(sample('k8s'));
        out = { checks: k.checks.length, fails: k.checks.filter(function (c) { return c.status === 'fail'; }).length, score: k.score };
        summaryText = out.fails + ' failing Kubernetes control(s).'; break; }
      case 'logs': { var lg = E.detectLogs(sample('logs'));
        out = { detections: (lg.detections || []).length, rules: DATA.LOG_RULES.length,
          iocs: (lg.iocs || []).length, lines: lg.stats.lines, at: lg.at };
        summaryText = out.detections + ' detection(s) from ' + out.rules + ' local MITRE-mapped rules.'; break; }
      case 'headers': { var hd = E.analyzeHeaders(sample('headers'));
        out = { checks: (hd.checks || []).length, grade: hd.grade, score: hd.score };
        summaryText = 'Hardening grade ' + hd.grade + ' across ' + out.checks + ' controls.'; break; }
      case 'secrets': { var sc = A.secretScan(sample('secrets'));
        var allMasked = sc.findings.every(function (f) { return f.masked.indexOf('•') !== -1 || f.masked.indexOf('****') !== -1; });
        out = { findings: sc.findings.length, score: sc.score, allMasked: allMasked,
          entropyMax: sc.findings.reduce(function (m, f) { return Math.max(m, f.entropy || 0); }, 0) };
        summaryText = sc.findings.length + ' credential-shaped string(s), values ' + (allMasked ? 'masked' : 'partially visible') + '.'; break; }
      case 'ingest': { var ng = A.normalizeLogs(sample('ingest'));
        out = { format: ng.format, events: ng.events.length, tagged: ng.stats.tagged, sources: ng.stats.sources };
        summaryText = ng.format + ' detected · ' + out.events + ' events normalized.'; break; }
      case 'chains': { var ch = A.attackChains(A.normalizeLogs(sample('ingest')));
        out = { chains: ch.chains.length, topConfidence: ch.chains.length ? ch.chains[0].confidence : 0 };
        summaryText = out.chains + ' multi-stage chain(s) reconstructed.'; break; }
      case 'coverage': { var cv = A.mitreCoverage(state);
        out = { covered: cv.covered, total: cv.total, percent: cv.percent };
        summaryText = cv.percent + '% ATT&CK technique coverage.'; break; }
      case 'plan': { var pl = plan(args.goal || '');
        out = { steps: pl.steps.length, eligible: pl.steps.filter(function (s) { return s.decision === 'ELIGIBLE'; }).length };
        summaryText = out.eligible + ' eligible offline step(s) in the plan.'; break; }
      case 'report': { out = { generatedAt: Date.now(), findings: (state.findings || []).length,
        alerts: (state.alerts || []).length, auditEntries: (state.audit || []).length };
        summaryText = 'Evidence report assembled from local state.'; break; }
      default: out = {}; summaryText = 'Adapter executed.';
    }
    return Object.assign(base, { result: {
      mode: 'offline-adapter', upstreamTool: t.id, capability: t.cap,
      engine: a.engine, label: a.label, summary: summaryText, data: out
    } });
  }

  var API = {
    UPSTREAM: UPSTREAM, AGENTS: AGENTS, TOOLS: TOOLS, MCP: MCP, ADAPTERS: ADAPTERS,
    summary: summary, get: get, tools: tools, evaluate: evaluate, plan: plan, call: call
  };
  root.AEGIS_HEXSTRIKE = API;
  if (isNode) module.exports = API;
})(typeof globalThis !== 'undefined' ? globalThis : this);
