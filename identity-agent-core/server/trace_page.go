package server

const traceViewerHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sandbox Trace Debugger</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0a0e1a;color:#c8d6e5;font-family:'Courier New',monospace;font-size:13px}
.app{display:flex;flex-direction:column;height:100vh}
.toolbar{display:flex;align-items:center;gap:12px;padding:8px 16px;background:#0d1224;border-bottom:1px solid #1a2744}
.toolbar h1{font-size:14px;color:#00ffc8;text-transform:uppercase;letter-spacing:2px}
.toolbar .spacer{flex:1}
.btn{background:#1a2744;color:#c8d6e5;border:1px solid #2a3a5c;padding:6px 14px;cursor:pointer;font-family:inherit;font-size:12px;border-radius:3px;transition:all .15s}
.btn:hover{background:#243352;border-color:#00ffc8}
.btn.active{background:#00ffc8;color:#0a0e1a;border-color:#00ffc8}
.btn.danger{border-color:#ff4757}
.btn.danger:hover{background:#ff4757;color:#fff}
.status{display:flex;align-items:center;gap:6px;font-size:11px}
.dot{width:8px;height:8px;border-radius:50%;display:inline-block}
.dot.on{background:#00ffc8;box-shadow:0 0 6px #00ffc8}
.dot.off{background:#555}
.main{display:flex;flex:1;overflow:hidden}
.sidebar{width:220px;background:#0d1224;border-right:1px solid #1a2744;display:flex;flex-direction:column}
.sidebar h3{padding:10px 12px 6px;font-size:11px;color:#5a6e8a;text-transform:uppercase;letter-spacing:1px}
.filter-group{padding:4px 12px}
.filter-group label{display:flex;align-items:center;gap:6px;padding:3px 0;cursor:pointer;font-size:12px;color:#8899aa}
.filter-group label:hover{color:#c8d6e5}
.filter-group input[type=checkbox]{accent-color:#00ffc8}
.module-dot{width:10px;height:10px;border-radius:2px;display:inline-block}
.module-dot.proxy{background:#3498db}
.module-dot.policy{background:#e67e22}
.module-dot.dns{background:#9b59b6}
.module-dot.credentials{background:#f39c12}
.module-dot.agent_api{background:#1abc9c}
.timeline{flex:1;display:flex;flex-direction:column;overflow:hidden}
.timeline-header{display:flex;align-items:center;gap:12px;padding:8px 16px;background:#0d1224;border-bottom:1px solid #1a2744;font-size:11px;color:#5a6e8a}
.timeline-header .count{color:#00ffc8}
.entries{flex:1;overflow-y:auto;padding:4px 0}
.entry{display:flex;align-items:flex-start;padding:6px 16px;border-bottom:1px solid #0f1730;cursor:pointer;transition:background .1s}
.entry:hover{background:#111b30}
.entry.selected{background:#152040;border-left:3px solid #00ffc8}
.entry-module{width:80px;flex-shrink:0;display:flex;align-items:center;gap:6px}
.entry-module .tag{padding:2px 6px;border-radius:2px;font-size:10px;text-transform:uppercase;font-weight:bold}
.tag.proxy{background:#3498db22;color:#3498db;border:1px solid #3498db44}
.tag.policy{background:#e67e2222;color:#e67e22;border:1px solid #e67e2244}
.tag.dns{background:#9b59b622;color:#9b59b6;border:1px solid #9b59b644}
.tag.credentials{background:#f39c1222;color:#f39c12;border:1px solid #f39c1244}
.tag.agent_api{background:#1abc9c22;color:#1abc9c;border:1px solid #1abc9c44}
.entry-time{width:90px;flex-shrink:0;color:#5a6e8a;font-size:11px}
.entry-dir{width:20px;flex-shrink:0;font-size:14px}
.entry-summary{flex:1;color:#c8d6e5;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.entry-stage{width:100px;flex-shrink:0;color:#5a6e8a;text-align:right;font-size:11px}
.detail-panel{width:400px;background:#0d1224;border-left:1px solid #1a2744;display:flex;flex-direction:column;overflow:hidden}
.detail-panel.hidden{display:none}
.detail-header{padding:10px 16px;border-bottom:1px solid #1a2744;display:flex;justify-content:space-between;align-items:center}
.detail-header h3{font-size:12px;color:#00ffc8}
.detail-body{flex:1;overflow-y:auto;padding:12px 16px}
.detail-section{margin-bottom:16px}
.detail-section h4{font-size:11px;color:#5a6e8a;text-transform:uppercase;margin-bottom:6px;letter-spacing:1px}
.detail-section pre{background:#0a0e1a;border:1px solid #1a2744;border-radius:3px;padding:8px;overflow-x:auto;font-size:11px;line-height:1.5;color:#c8d6e5}
.detail-row{display:flex;gap:8px;padding:3px 0;font-size:12px}
.detail-row .label{color:#5a6e8a;min-width:80px}
.detail-row .value{color:#c8d6e5;word-break:break-all}
.empty{display:flex;align-items:center;justify-content:center;flex:1;color:#3a4a6a;font-size:14px;flex-direction:column;gap:8px}
.step-controls{display:flex;gap:8px;align-items:center;padding:8px 16px;background:#1a0e24;border-bottom:1px solid #2a1744}
.step-controls.hidden{display:none}
::-webkit-scrollbar{width:6px}
::-webkit-scrollbar-track{background:#0a0e1a}
::-webkit-scrollbar-thumb{background:#1a2744;border-radius:3px}
::-webkit-scrollbar-thumb:hover{background:#2a3a5c}
</style>
</head>
<body>
<div class="app">
<div class="toolbar">
<h1>Trace Debugger</h1>
<div class="status">
<span class="dot" id="statusDot"></span>
<span id="statusText">Disconnected</span>
</div>
<div class="spacer"></div>
<button class="btn" id="btnToggle" onclick="toggleTrace()">Enable</button>
<button class="btn" id="btnStepMode" onclick="toggleStepMode()">Step Mode</button>
<button class="btn danger" onclick="clearEntries()">Clear</button>
<button class="btn" onclick="loadHistory()">Load History</button>
</div>
<div class="step-controls hidden" id="stepControls">
<span style="color:#9b59b6;font-size:11px">STEP MODE ACTIVE</span>
<div class="spacer" style="flex:1"></div>
</div>
<div class="main">
<div class="sidebar">
<h3>Modules</h3>
<div class="filter-group" id="moduleFilters">
<label><input type="checkbox" checked data-module="proxy"><span class="module-dot proxy"></span> Proxy</label>
<label><input type="checkbox" checked data-module="policy"><span class="module-dot policy"></span> Policy</label>
<label><input type="checkbox" checked data-module="dns"><span class="module-dot dns"></span> DNS</label>
<label><input type="checkbox" checked data-module="credentials"><span class="module-dot credentials"></span> Credentials</label>
<label><input type="checkbox" checked data-module="agent_api"><span class="module-dot agent_api"></span> Agent API</label>
</div>
<h3>Direction</h3>
<div class="filter-group" id="dirFilters">
<label><input type="checkbox" checked data-dir="egress"> Egress</label>
<label><input type="checkbox" checked data-dir="ingress"> Ingress</label>
</div>
<h3>Sessions</h3>
<div id="sessionList" style="padding:4px 12px;font-size:11px;color:#5a6e8a">No active sessions</div>
</div>
<div class="timeline">
<div class="timeline-header">
<span>LIVE TRACE</span>
<span class="count" id="entryCount">0 entries</span>
<div style="flex:1"></div>
<label style="font-size:11px;display:flex;align-items:center;gap:4px;cursor:pointer">
<input type="checkbox" id="autoScroll" checked style="accent-color:#00ffc8"> Auto-scroll
</label>
</div>
<div class="entries" id="entriesContainer">
<div class="empty" id="emptyState">
<div>No trace entries yet</div>
<div style="font-size:12px">Enable tracing and trigger sandbox requests</div>
</div>
</div>
</div>
<div class="detail-panel hidden" id="detailPanel">
<div class="detail-header">
<h3 id="detailTitle">Entry Detail</h3>
<button class="btn" onclick="closeDetail()" style="padding:2px 8px">X</button>
</div>
<div class="detail-body" id="detailBody"></div>
</div>
</div>
</div>
<script>
let ws=null,entries=[],selectedIdx=-1,traceEnabled=false,stepMode=false;
const baseUrl=window.location.origin;
const moduleColors={proxy:'#3498db',policy:'#e67e22',dns:'#9b59b6',credentials:'#f39c12',agent_api:'#1abc9c'};

function connectWS(){
const proto=location.protocol==='https:'?'wss':'ws';
ws=new WebSocket(proto+'://'+location.host+'/ws/trace');
ws.onopen=()=>{document.getElementById('statusDot').className='dot on';document.getElementById('statusText').textContent='Connected'};
ws.onclose=()=>{document.getElementById('statusDot').className='dot off';document.getElementById('statusText').textContent='Disconnected';setTimeout(connectWS,2000)};
ws.onerror=()=>ws.close();
ws.onmessage=(e)=>{
try{const entry=JSON.parse(e.data);addEntry(entry)}catch(err){}
};
}

function addEntry(entry){
entries.push(entry);
if(entries.length>5000)entries=entries.slice(-4000);
document.getElementById('entryCount').textContent=entries.length+' entries';
document.getElementById('emptyState').style.display='none';
if(isVisible(entry))renderEntry(entry,entries.length-1);
}

function isVisible(entry){
const modChecks=document.querySelectorAll('#moduleFilters input');
const dirChecks=document.querySelectorAll('#dirFilters input');
let modOk=false,dirOk=false;
modChecks.forEach(c=>{if(c.checked&&c.dataset.module===entry.module)modOk=true});
dirChecks.forEach(c=>{if(c.checked&&c.dataset.dir===entry.direction)dirOk=true});
return modOk&&dirOk;
}

function renderEntry(entry,idx){
const container=document.getElementById('entriesContainer');
const div=document.createElement('div');
div.className='entry';
div.dataset.idx=idx;
div.onclick=()=>selectEntry(idx);
const ts=new Date(entry.timestamp).toLocaleTimeString('en-US',{hour12:false,hour:'2-digit',minute:'2-digit',second:'2-digit',fractionalSecondDigits:3});
const dirIcon=entry.direction==='egress'?'\u2192':'\u2190';
div.innerHTML='<div class="entry-module"><span class="tag '+entry.module+'">'+entry.module+'</span></div>'
+'<div class="entry-time">'+ts+'</div>'
+'<div class="entry-dir">'+dirIcon+'</div>'
+'<div class="entry-summary">'+escHtml(entry.summary)+'</div>'
+'<div class="entry-stage">'+entry.stage+'</div>';
container.appendChild(div);
if(document.getElementById('autoScroll').checked)container.scrollTop=container.scrollHeight;
}

function selectEntry(idx){
selectedIdx=idx;
document.querySelectorAll('.entry').forEach(e=>e.classList.remove('selected'));
const el=document.querySelector('.entry[data-idx="'+idx+'"]');
if(el)el.classList.add('selected');
const entry=entries[idx];
if(!entry)return;
const panel=document.getElementById('detailPanel');
panel.classList.remove('hidden');
document.getElementById('detailTitle').textContent=entry.module+' / '+entry.stage;
const body=document.getElementById('detailBody');
body.innerHTML='<div class="detail-section"><h4>Overview</h4>'
+row('ID',entry.id)+row('Trace ID',entry.trace_id||'(global)')
+row('Module',entry.module)+row('Stage',entry.stage)+row('Direction',entry.direction)
+row('App ID',entry.app_id||'-')+row('Instance',entry.instance_id||'-')
+row('Timestamp',new Date(entry.timestamp).toISOString())
+row('Sequence',entry.seq||'-')
+'</div>'
+'<div class="detail-section"><h4>Summary</h4><pre>'+escHtml(entry.summary)+'</pre></div>';
if(entry.detail&&Object.keys(entry.detail).length>0){
body.innerHTML+='<div class="detail-section"><h4>Detail</h4><pre>'+escHtml(JSON.stringify(entry.detail,null,2))+'</pre></div>';
}
}

function row(label,value){return '<div class="detail-row"><span class="label">'+label+'</span><span class="value">'+(value||'-')+'</span></div>'}
function escHtml(s){if(!s)return'';return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}
function closeDetail(){document.getElementById('detailPanel').classList.add('hidden');selectedIdx=-1}

async function toggleTrace(){
const url=traceEnabled?'/api/trace/disable':'/api/trace/enable';
const r=await fetch(baseUrl+url,{method:'POST'});
const d=await r.json();
traceEnabled=d.enabled;
updateToggleBtn();
}

async function toggleStepMode(){
stepMode=!stepMode;
await fetch(baseUrl+'/api/trace/step-mode',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({enabled:stepMode})});
document.getElementById('btnStepMode').classList.toggle('active',stepMode);
document.getElementById('stepControls').classList.toggle('hidden',!stepMode);
}

function updateToggleBtn(){
const btn=document.getElementById('btnToggle');
btn.textContent=traceEnabled?'Disable':'Enable';
btn.classList.toggle('active',traceEnabled);
}

async function clearEntries(){
await fetch(baseUrl+'/api/trace/clear',{method:'POST'});
entries=[];
document.getElementById('entriesContainer').innerHTML='<div class="empty" id="emptyState"><div>No trace entries yet</div><div style="font-size:12px">Enable tracing and trigger sandbox requests</div></div>';
document.getElementById('entryCount').textContent='0 entries';
closeDetail();
}

async function loadHistory(){
const r=await fetch(baseUrl+'/api/trace/entries?limit=500');
const d=await r.json();
if(d.entries&&d.entries.length>0){
entries=d.entries;
rerenderAll();
}
}

function rerenderAll(){
const container=document.getElementById('entriesContainer');
container.innerHTML='';
let shown=0;
entries.forEach((e,i)=>{if(isVisible(e)){renderEntry(e,i);shown++}});
if(shown===0)container.innerHTML='<div class="empty" id="emptyState"><div>No matching entries</div></div>';
document.getElementById('entryCount').textContent=entries.length+' entries ('+shown+' shown)';
}

document.querySelectorAll('#moduleFilters input, #dirFilters input').forEach(c=>c.addEventListener('change',rerenderAll));

async function checkStatus(){
try{
const r=await fetch(baseUrl+'/api/trace/status');
const d=await r.json();
traceEnabled=d.enabled;
stepMode=d.step_mode;
updateToggleBtn();
document.getElementById('btnStepMode').classList.toggle('active',stepMode);
document.getElementById('stepControls').classList.toggle('hidden',!stepMode);
}catch(e){}
}

async function init(){
await checkStatus();
if(!traceEnabled){
await fetch(baseUrl+'/api/trace/enable',{method:'POST'});
traceEnabled=true;
updateToggleBtn();
}
await loadHistory();
connectWS();
}
init();
</script>
</body>
</html>`
