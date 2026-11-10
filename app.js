(() => {
  const output = document.getElementById('terminalOutput');
  const form = document.getElementById('terminalForm');
  const input = document.getElementById('terminalInput');
  const history = [];
  let historyIndex = 0;
  let startedAt = Date.now();
  const safeCommands = ['help','clear','pwd','whoami','date','ls','status','tools','scan','inspect','audit','hash','echo'];
  const toolNames = ['Network Mapper','Web Inspector','Config Auditor','Hash Lab','Packet Viewer','Log Analyzer','TLS Check','DNS Explorer','File Integrity','Header Review','Port Atlas','Threat Notes','Subdomain Map','Cookie Inspector','Certificate Viewer','Permission Lens','Timeline Builder','YARA Tutor','Entropy Meter','Regex Workshop','Linux Basics','HTTP Sandbox','Syslog Reader','Safe Encoder'];
  const nowTime = () => new Date().toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'});
  function addLine(text, cls='output-text') { const line=document.createElement('div'); line.className=`terminal-line ${cls}`; line.textContent=text; output.appendChild(line); output.scrollTop=output.scrollHeight; }
  function promptLine(command) { const line=document.createElement('div'); line.className='terminal-line'; const prompt=document.createElement('span');prompt.className='prompt';prompt.textContent='operator@nightshift';const path=document.createElement('span');path.className='path';path.textContent=':~$';const cmd=document.createElement('span');cmd.className='command-text';cmd.textContent=` ${command}`;line.append(prompt,path,cmd);output.appendChild(line);output.scrollTop=output.scrollHeight; }
  function record(command) { const list=document.getElementById('activityList'); const row=document.createElement('div');row.className='activity-item';row.innerHTML='<span class="activity-marker green-marker">⌘</span><div></div><time></time>';row.children[1].innerHTML=`<strong></strong><small></small>`;row.children[1].children[0].textContent=`Command: ${command}`;row.children[1].children[1].textContent='Simulated · local only';row.children[2].textContent=nowTime();list.prepend(row);while(list.children.length>5)list.lastElementChild.remove(); }
  function run(raw) {
    const command=raw.trim(); if(!command)return; history.push(command);historyIndex=history.length;promptLine(command);record(command);
    const [verb,...args]=command.split(/\s+/);const arg=args.join(' ');
    switch(verb.toLowerCase()) {
      case 'help': addLine('Available safe commands:'); addLine('  help, clear, pwd, whoami, date, ls, status, tools'); addLine('  scan <lab.local>   inspect the fictional training network'); addLine('  inspect <lab.local> review a sample web application'); addLine('  audit <demo.local> check simulated security settings'); addLine('  hash <demo.txt>    demonstrate a sample file fingerprint'); addLine('  echo <text>        print text in this session'); addLine('Only these simulated commands are supported. No system shell is connected.'); break;
      case 'clear': output.innerHTML='';break;
      case 'pwd': addLine('/home/operator/training-lab');break;
      case 'whoami': addLine('operator (unprivileged training account)');break;
      case 'date': addLine(new Date().toString());break;
      case 'ls': addLine('README.lab   notes.txt   samples/   reports/');addLine('These are fictional files in the training workspace.');break;
      case 'status': addLine('LAB STATUS      READY');addLine('NETWORK         ISOLATED · 192.168.56.0/24 (simulated)');addLine('HOST ACCESS     NONE');addLine('EXTERNAL I/O    DISABLED');addLine('TOOLS           24 educational simulators');break;
      case 'tools': addLine('EDUCATIONAL TOOLKIT · 24 SIMULATORS');toolNames.forEach((n,i)=>addLine(`  ${(i+1).toString().padStart(2,'0')}  ${n}`));break;
      case 'scan': if(!arg){addLine('Usage: scan lab.local');break;} if(!['lab.local','192.168.56.10'].includes(arg)){addLine('Target not in the fictional lab inventory. Try: scan lab.local');break;} addLine(`Starting simulated discovery against ${arg} (training data only)...`);addLine('HOST       STATUS    SERVICES');addLine('lab.local  UP        22/tcp (training SSH), 80/tcp (sample web)');addLine('Scan complete: 1 fictional host · no packets sent.');break;
      case 'inspect': if(!arg){addLine('Usage: inspect lab.local');break;} if(!['lab.local','demo.local'].includes(arg)){addLine('Only lab.local and demo.local exist in this simulation.');break;} addLine(`Sample app review: ${arg}`);addLine('  HTTPS: enabled in training profile');addLine('  Content-Security-Policy: report-only (learning opportunity)');addLine('  X-Content-Type-Options: nosniff');addLine('No real website was contacted.');break;
      case 'audit': if(!arg){addLine('Usage: audit demo.local');break;} if(!['demo.local','lab.local'].includes(arg)){addLine('Use the included fictional target: audit demo.local');break;} addLine(`Defensive config audit for ${arg} (sample dataset):`);addLine('  [PASS] HTTPS redirect configured');addLine('  [WARN] Referrer-Policy could be stricter');addLine('  [PASS] Secure cookie flag present');addLine('  Result: 2 pass · 1 learning note');break;
      case 'hash': if(!arg){addLine('Usage: hash demo.txt');break;} if(arg!=='demo.txt'){addLine('Only demo.txt is available in this isolated exercise.');break;} addLine('SHA-256  demo.txt');addLine('9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08');addLine('Educational sample fingerprint; no local files were read.');break;
      case 'echo': addLine(arg||'');break;
      default: addLine(`Command not available: ${verb}`,'error-line');addLine('This is not a real Linux shell. Type help to see the safe, simulated commands.');
    }
  }
  form.addEventListener('submit',e=>{e.preventDefault();run(input.value);input.value='';});
  input.addEventListener('keydown',e=>{if(e.key==='ArrowUp'){e.preventDefault();if(historyIndex>0){historyIndex--;input.value=history[historyIndex]||'';}}if(e.key==='ArrowDown'){e.preventDefault();if(historyIndex<history.length-1){historyIndex++;input.value=history[historyIndex]||'';}else{historyIndex=history.length;input.value='';}}});
  document.querySelectorAll('[data-command]').forEach(button=>button.addEventListener('click',()=>{document.getElementById('terminal').scrollIntoView({behavior:'smooth',block:'center'});run(button.dataset.command);}));
  document.getElementById('clearTerminal').addEventListener('click',()=>{output.innerHTML='';input.focus();});
  let toastTimer;function toast(message){const el=document.getElementById('toast');el.textContent=message;el.classList.add('show');clearTimeout(toastTimer);toastTimer=setTimeout(()=>el.classList.remove('show'),2600);}
  document.getElementById('newLab').addEventListener('click',()=>{startedAt=Date.now();toast('Fresh isolated lab session started.');run('status');});
  document.getElementById('tourButton').addEventListener('click',()=>toast('Tour: try the safe terminal commands and explore the fictional lab tools.'));
  document.getElementById('topologyButton').addEventListener('click',()=>toast('Topology is a visual simulation. No network connections are active.'));
  document.getElementById('activityButton').addEventListener('click',()=>toast(`${history.length} simulated command${history.length===1?'':'s'} recorded in this local session.`));
  document.getElementById('themeButton').addEventListener('click',()=>{document.body.classList.toggle('high-contrast');toast('Display contrast updated.');});
  document.querySelectorAll('.nav-item').forEach(link=>link.addEventListener('click',()=>{document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active'));link.classList.add('active');}));
  setInterval(()=>{const seconds=Math.floor((Date.now()-startedAt)/1000);const hh=String(Math.floor(seconds/3600)).padStart(2,'0');const mm=String(Math.floor((seconds%3600)/60)).padStart(2,'0');const ss=String(seconds%60).padStart(2,'0');document.getElementById('sessionClock').innerHTML=`${hh}:${mm}<span class="stat-unit">:${ss}</span>`;},1000);
})();
