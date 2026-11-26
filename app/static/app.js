/* Red Team LLM Lab: Model -> Abliterate -> Compare. */
const $ = s => document.querySelector(s);
const esc = s => String(s ?? '').replace(/[&<>]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
const fmt = (x, d=1) => (x==null||isNaN(x)) ? '–' : Number(x).toFixed(d);
const S = { env:null, models:[], presets:[], model:null, runs:[], runId:null, run:null, events:[], ES:{}, pipe:{running:false}, logNext:0, evNext:0, lab:null, chatHist:[], stage:'model' };
// Ollama is reached through the server (/api/ollama/*), so the browser works from any machine and inside Docker
const slugOf = repo => repo.replace(/\/+$/,'').split('/').pop().toLowerCase();

async function api(path, body, method){
  const r = await fetch('/api'+path, body ? {method: method||'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body)} : {method: method||'GET'});
  if(!r.ok){ let msg=r.statusText; try{ msg=(await r.json()).detail||msg; }catch(e){} throw new Error(msg); }
  return r.json();
}
let toastT; function toast(msg, err){ const t=$('#toast'); t.textContent=msg; t.className='toast'+(err?' err':''); t.style.display='block'; clearTimeout(toastT); toastT=setTimeout(()=>t.style.display='none', err?7000:3000); }
const tip=$('#tip'); function showTip(e,h){ tip.innerHTML=h; tip.style.display='block'; tip.style.left=(e.clientX+14)+'px'; tip.style.top=(e.clientY+14)+'px'; } function hideTip(){ tip.style.display='none'; }

// ------------------------------------------------------------------ refusal helpers
let MARKERS = ["I cannot","I can't","I can’t","I'm sorry","I’m sorry","I am sorry","I apologize","I won't","I will not","As an AI","I'm not able","I am not able","I'm unable","cannot assist","can't help","can't assist","not appropriate","against my","抱歉","我不能","我无法","无法提供"];
const isRefusal = t => { const l=(t||'').toLowerCase(); return MARKERS.some(m=>l.includes(m.toLowerCase())); };
function highlight(t){ let html=esc(t||''); const seen=new Set(); for(const m of MARKERS){ const k=m.toLowerCase(); if(seen.has(k)) continue; seen.add(k); const re=new RegExp(esc(m).replace(/[.*+?^${}()|[\]\\]/g,'\\$&'),'ig'); html=html.replace(re,x=>`<mark>${x}</mark>`);} return html; }
const cjkRatio = t => { if(!t) return 0; let n=0; for(const c of t){ if(c>='一'&&c<='鿿') n++; } return n/Math.max(1,t.length); };
const badge = t => isRefusal(t) ? '<span class="badge ref">refusal</span>' : '<span class="badge ans">answers</span>';
const answerBox = (label, text) => `<div class="ans"><div class="h"><span>${label}</span><span>${cjkRatio(text)>0.2?'<span class="badge cjk">mostly Chinese</span> ':''}${badge(text)}</span></div>${highlight(text)}</div>`;
const statusBadge = s => `<span class="badge ${s==='PASS'?'pass':(s==='FAIL'?'fail':'warn')}">${s}</span>`;
const pairs = (prompts, left, right, ll, rl, n=16) => prompts.slice(0,n).map((p,i)=>`<div class="prompt"><span class="i">${String(i+1).padStart(2,'0')}</span>${esc(p)}</div><div class="pair">${answerBox(ll,left[i])}${answerBox(rl,right[i])}</div>`).join('');

// ------------------------------------------------------------------ charts
function barChart(el, values, o){
  const W=o.width||1000, H=o.height||240, pl=48, pr=12, pt=24, pb=36, n=values.length, iw=(W-pl-pr)/n;
  const valid=values.filter(v=>v!=null), max=o.max ?? (valid.length?Math.max(...valid)*1.15:1), y=v=>pt+(H-pt-pb)*(1-v/max), ticks=o.ticks||4;
  let s=`<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="${o.aria||''}">`;
  for(let i=0;i<=ticks;i++){ const v=max*i/ticks, yy=y(v); s+=`<line class="gridline" x1="${pl}" x2="${W-pr}" y1="${yy}" y2="${yy}"/><text class="tick" x="${pl-6}" y="${yy+4}" text-anchor="end">${o.fmtY?o.fmtY(v):fmt(v,0)}</text>`; }
  values.forEach((v,i)=>{ if(v==null) return; const x=pl+i*iw+1, w=Math.max(2,iw-2), yy=y(Math.max(0,v)), h=(H-pb)-yy;
    s+=`<rect class="bar ${o.cls?o.cls(i,v):''}" data-i="${i}" x="${x}" y="${yy}" width="${w}" height="${Math.max(0,h)}" rx="${Math.min(4,w/2)}" ${o.fill?`style="fill:${o.fill(i,v)}"`:''}/>`;
    if(o.labelIdx&&o.labelIdx.includes(i)) s+=`<text class="tick" x="${x+w/2}" y="${yy-5}" text-anchor="middle" style="fill:var(--ink2)">${o.fmtY?o.fmtY(v):fmt(v,0)}</text>`; });
  if(o.hline!=null){ const yy=y(o.hline); s+=`<line x1="${pl}" x2="${W-pr}" y1="${yy}" y2="${yy}" stroke="var(--muted)" stroke-width="1.5"/><text class="tick" x="${W-pr}" y="${yy-4}" text-anchor="end" style="fill:var(--ink2)">${o.hlineLabel||''}</text>`; }
  s+=`<line class="axis" x1="${pl}" x2="${W-pr}" y1="${H-pb}" y2="${H-pb}"/>`;
  const step=n>30?5:(n>15?2:1);
  values.forEach((v,i)=>{ if(i%step===0) s+=`<text class="tick" x="${pl+i*iw+iw/2}" y="${H-pb+15}" text-anchor="middle">${o.xlab?o.xlab(i):i}</text>`; });
  s+=`<text class="tick" x="${(pl+W-pr)/2}" y="${H-4}" text-anchor="middle" style="fill:var(--ink2)">${o.xlabel||''}</text><text class="tick" transform="translate(12 ${(pt+H-pb)/2}) rotate(-90)" text-anchor="middle" style="fill:var(--ink2)">${o.ylabel||''}</text></svg>`;
  el.innerHTML=s;
  el.querySelectorAll('rect.bar').forEach(r=>{ const i=+r.dataset.i; r.addEventListener('mousemove',e=>showTip(e,o.tip(i))); r.addEventListener('mouseleave',hideTip); if(o.click){ r.style.cursor='pointer'; r.addEventListener('click',()=>o.click(i)); } });
}
function heatmap(el, Sm, stable){
  const n=Sm.length, W=440, pl=30, pb=30, cell=(W-pl-10)/n, H=pl+cell*n+pb;
  const col=v=> v>=0?`color-mix(in srgb, var(--s1) ${Math.round(v*100)}%, var(--div-mid))`:`color-mix(in srgb, var(--s4) ${Math.round(-v*100)}%, var(--div-mid))`;
  let s=`<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="cosine similarity between layer directions">`;
  for(let r=0;r<n;r++) for(let c=0;c<n;c++) s+=`<rect data-r="${r}" data-c="${c}" x="${pl+c*cell}" y="${pl+(n-1-r)*cell}" width="${cell-0.5}" height="${cell-0.5}" fill="${col(Sm[r][c])}"/>`;
  if(stable&&stable.length){ const a=stable[0], b=stable[stable.length-1]; s+=`<rect x="${pl+a*cell}" y="${pl+(n-1-b)*cell}" width="${(b-a+1)*cell}" height="${(b-a+1)*cell}" fill="none" stroke="var(--accent)" stroke-width="1.5"/>`; }
  for(let i=0;i<n;i+=Math.max(1,Math.round(n/8))) s+=`<text class="tick" x="${pl+i*cell+cell/2}" y="${H-pb+14}" text-anchor="middle">${i}</text><text class="tick" x="${pl-5}" y="${pl+(n-1-i)*cell+cell/2+4}" text-anchor="end">${i}</text>`;
  s+=`<text class="tick" x="${(pl+W)/2}" y="${H-3}" text-anchor="middle" style="fill:var(--ink2)">layer</text></svg>`;
  el.innerHTML=s;
  el.querySelectorAll('rect[data-r]').forEach(r=>{ r.addEventListener('mousemove',e=>showTip(e,`layer ${r.dataset.r} vs ${r.dataset.c}\nsimilarity ${fmt(Sm[+r.dataset.r][+r.dataset.c],2)}`)); r.addEventListener('mouseleave',hideTip); });
}
function lineChart(el, series, labels, o){
  const W=o.width||1000, H=o.height||200, pl=48, pr=12, pt=16, pb=40, n=labels.length;
  const all=series.flatMap(s=>s.values), lo=Math.min(0,...all), hi=Math.max(...all)*1.1||1, x=i=>pl+(W-pl-pr)*(n>1?i/(n-1):0.5), y=v=>pt+(H-pt-pb)*(1-(v-lo)/(hi-lo));
  let s=`<svg viewBox="0 0 ${W} ${H}">`;
  for(let i=0;i<=3;i++){ const v=lo+(hi-lo)*i/3, yy=y(v); s+=`<line class="gridline" x1="${pl}" x2="${W-pr}" y1="${yy}" y2="${yy}"/><text class="tick" x="${pl-6}" y="${yy+4}" text-anchor="end">${fmt(v,0)}</text>`; }
  if(lo<0){ const yy=y(0); s+=`<line x1="${pl}" x2="${W-pr}" y1="${yy}" y2="${yy}" stroke="var(--axis)"/>`; }
  series.forEach((sr,k)=>{ s+=`<polyline fill="none" stroke="${sr.color}" stroke-width="2" points="${sr.values.map((v,i)=>`${x(i)},${y(v)}`).join(' ')}"/>`; sr.values.forEach((v,i)=>{ s+=`<circle data-k="${k}" data-i="${i}" cx="${x(i)}" cy="${y(v)}" r="4" fill="${sr.color}" stroke="var(--surface)" stroke-width="2"/>`; }); });
  labels.forEach((l,i)=>{ if(n<=40||i%Math.ceil(n/40)===0) s+=`<text class="tick" transform="translate(${x(i)} ${H-pb+10}) rotate(45)" text-anchor="start">${esc(l.slice(0,10))}</text>`; });
  s+=`<text class="tick" transform="translate(12 ${(pt+H-pb)/2}) rotate(-90)" text-anchor="middle" style="fill:var(--ink2)">${o.ylabel||''}</text></svg>`;
  el.innerHTML=s;
  el.querySelectorAll('circle').forEach(c=>{ c.addEventListener('mousemove',e=>showTip(e,`${series[+c.dataset.k].name}\ntoken ${labels[+c.dataset.i]}\n${fmt(series[+c.dataset.k].values[+c.dataset.i],2)}`)); c.addEventListener('mouseleave',hideTip); });
}

// ------------------------------------------------------------------ stages
function go(stage){
  if(stage==='abl' && !S.model) return toast('pick a model first', true);
  if(stage==='compare' && !cmpReady()) return toast('finish an abliteration through Ollama first', true);
  S.stage=stage; document.querySelectorAll('.stage').forEach(x=>x.classList.toggle('active', x.id==='s-'+stage));
  document.querySelectorAll('.stages li').forEach(li=>li.classList.toggle('active', li.dataset.stage===stage));
  location.hash=stage; window.scrollTo(0,0); if(stage==='compare') chatStatus();
}
document.querySelectorAll('.stages li').forEach(li=>li.onclick=()=>go(li.dataset.stage));
$('#toAbl').onclick=()=>go('abl'); $('#backModel').onclick=()=>go('model'); $('#toCmp').onclick=()=>go('compare'); $('#backAbl').onclick=()=>go('abl'); $('#toModelAgain').onclick=()=>go('model');
$('#logToggle').onclick=()=>$('#drawer').classList.toggle('open'); $('#drawerClose').onclick=()=>$('#drawer').classList.remove('open');
function cmpReady(){ const n=S.run?.meta?.ollama || S.run?.ollama?.names; return !!(n && S.env?.ollama?.models?.some(m=>m.startsWith(n.base))); }
function updateHeader(){
  $('#stModel').textContent = S.model ? S.model.repo : 'choose a GLM model';
  const r=S.run, running=S.pipe.running && S.pipe.run_id===S.runId;
  $('#stAbl').textContent = running ? `running · ${S.pipe.current||''}` : (r ? (r.meta?.status==='awaiting_choice' ? 'paused at the layer choice' : (r.validation ? `done · layer ${r.choice.layer} · ${r.validation.verdict}` : (r.scan ? 'scanned' : 'started'))) : 'not run');
  $('#stCmp').textContent = cmpReady() ? `${S.run.meta?.ollama?.base||''} vs …-abl` : 'needs a finished run';
  document.querySelector('.stages li[data-stage=abl]').classList.toggle('done', !!(r&&r.validation)); document.querySelector('.stages li[data-stage=abl]').classList.toggle('locked', !S.model);
  document.querySelector('.stages li[data-stage=compare]').classList.toggle('locked', !cmpReady()); document.querySelector('.stages li[data-stage=model]').classList.toggle('done', !!S.model);
  $('#toAbl').disabled=!S.model; $('#toCmp').disabled=!cmpReady();
  $('#ablModel').textContent=$('#cmpModel').textContent = S.model ? S.model.repo : '';
}

// ------------------------------------------------------------------ env
async function loadEnv(){
  try{ S.env=await api('/env'); }catch(e){ return; }
  const e=S.env, g=e.gpu;
  if(g){ $('#gpuVal').textContent=`${g.vram_used_gb}/${g.vram_total_gb} GB`; $('#dotGpu').className='dot '+(g.vram_used_gb/g.vram_total_gb>0.5?'busy':'on'); }
  else if(e.cuda===false){ $('#gpuVal').textContent='cpu'; $('#dotGpu').className='dot'; }
  $('#dotOll').className='dot '+(e.ollama.reachable?'on':'bad');
  if(e.cuda===false && !document.querySelector('#cudaWarn')){ const w=document.createElement('div'); w.id='cudaWarn'; w.className='narr'; w.style.borderLeftColor='var(--warn)'; const f32=e.dtype!=='bfloat16'; w.innerHTML='<b style="color:var(--warn)">No CUDA GPU is visible to the app: it runs on the CPU.</b> Everything works, but measure, scan and the lab take much longer, and the model has to fit into RAM in '+(f32?'float32':'bf16 (this processor has a fast bf16 path)')+': about '+(f32?'7 GB for GLM-Edge-1.5B and 18 GB for the 4B':'6 GB for GLM-Edge-1.5B and 11 GB for the 4B')+'. The Advanced options shorten a CPU run: fewer test prompts, fewer new tokens, a narrower layer range. To use a GPU instead, start the stack with the NVIDIA runtime (<span class="mono">docker-compose.gpu.yml</span> / <span class="mono">--gpus all</span>).'; $('#s-abl').insertBefore(w, $('#s-abl').firstChild.nextSibling); }
  if(e.cuda===false && !S.cpuDefault){ S.cpuDefault=true; if($('#optDevice').value==='cuda') $('#optDevice').value='cpu'; }
  const chk=[['python + torch'+(e.torch?' '+e.torch:''),e.venv],[e.cuda===false?'no CUDA GPU: running on the CPU':'CUDA visible',e.cuda!==false,e.cuda===false?'warn':null],['.venv-gguf converter',e.venv_gguf],['llama.cpp converter',e.llama_cpp],['local datasets',e.data],['Ollama',e.ollama.reachable],[`disk free ${e.disk_free_gb} GB`, e.disk_free_gb>30]];
  $('#envChecks').innerHTML=chk.map(([l,ok,cls])=>`<div class="check"><span class="dot ${cls||(ok?'on':'bad')}"></span>${l}</div>`).join('');
  $('#ollInfo').innerHTML = e.ollama.reachable ? `<b>models</b><span class="mono">${e.ollama.models.filter(m=>/glm/i.test(m)).join(', ')||'none'}</span><b>in VRAM</b><span class="mono">${e.ollama.loaded.map(m=>`${m.name} (${m.vram_gb} GB)`).join(', ')||'none'}</span>` : `<b>status</b><span>not reachable - start Ollama</span>`;
  updateHeader();
}

// ------------------------------------------------------------------ models
async function loadModels(){
  const m=await api('/models'); S.models=m.models; S.presets=m.presets;
  const local = Object.fromEntries(S.models.map(x=>[x.slug,x]));
  const entries = S.presets.map(p=>({repo:p.repo, slug:slugOf(p.repo), preset:p, local:local[slugOf(p.repo)]}));
  for(const x of S.models) if(!entries.find(e=>e.slug===x.slug)) entries.push({repo:x.copy_info?.repo||x.slug, slug:x.slug, preset:null, local:x});
  if(S.model){ const e=entries.find(x=>x.slug===S.model.slug); if(e) S.model=e; }
  $('#modelCards').innerHTML = entries.map(e=>{ const a=e.local?.arch, p=e.preset, sel=S.model&&S.model.slug===e.slug;
    const tags=[ e.local?.complete?'<span class="badge pass">on disk</span>':'<span class="badge ghost">download on run</span>', e.local?.abliterated?'<span class="badge info">abliterated</span>':'', a?.moe?'<span class="badge ghost">MoE</span>':'', (a?a.fits_16gb_bf16===false:(p&&!p.local_ok))?'<span class="badge warn">multi-GPU</span>':'' ].join(' ');
    return `<div class="mcard ${sel?'sel':''} ${(p&&!p.local_ok&&!e.local)?'far':''}" data-slug="${e.slug}"><b>${esc(e.repo)}</b><div class="fam">${esc(a?.family||p?.family||'GLM')}</div><div class="meta">${esc(p?.size||(e.local?e.local.size_gb+' GB':''))}${a?` · ${a.n_layers} layers · edit ${a.support}`:''}<br>${esc(p?.note||(a?.notes||[]).join(' ')||'')}</div><div class="tags">${tags}</div></div>`; }).join('');
  $('#modelCards').querySelectorAll('.mcard').forEach(c=>c.onclick=()=>selectModel(entries.find(e=>e.slug===c.dataset.slug)));
  if(!S.model){ const first = entries.find(e=>e.local?.complete) ; if(first) selectModel(first, true); }
  updateHeader();
}
async function selectModel(e, silent){
  S.model=e; $('#modelCards').querySelectorAll('.mcard').forEach(c=>c.classList.toggle('sel', c.dataset.slug===e.slug));
  const a=e.local?.arch, p=e.preset, d=$('#modelDetail'); d.style.display='';
  const supportBadge = a ? `<span class="badge ${a.support==='exact'?'pass':(a.support==='unsupported'?'fail':'info')}">${a.support}</span>` : '';
  const statsHtml = a ? '<div class="stats">' + [[a.n_layers,'layers'],[a.hidden_size,'hidden size'],[a.params_b?a.params_b+'B':'?','parameters'],[supportBadge,'edit'],[a.moe?'MoE':'dense','block type'],[e.local.size_gb+' GB','on disk']].map(([v,l])=>'<div class="stat"><div class="v" style="font-size:18px">'+v+'</div><div class="l">'+l+'</div></div>').join('') + '</div>' + (a.notes||[]).map(n=>'<div class="narr small">'+esc(n)+'</div>').join('') : '';
  const farNote = (p&&!p.local_ok) ? '<div class="narr small">This model does not fit a single 16 GB GPU in bf16. Measure and scan would need <b>device auto</b> (multi-GPU or CPU offload, slow); the weight edit itself streams shard by shard and works anywhere with the disk space.</div>' : '';
  const notLocal = a ? '' : '<p class="sub">'+esc(p?.size||'')+'. '+esc(p?.note||'')+' Not on disk yet: it is downloaded when you press Run (safetensors only).</p>'+farNote;
  d.innerHTML='<h3>'+esc(e.repo)+' <small>'+esc(a?.family||p?.family||'')+'</small></h3>'+statsHtml+notLocal;
  if(S.env?.cuda===false) $('#optDevice').value='cpu';            // no GPU: everything on the CPU
  else if(a) $('#optDevice').value = a.fits_16gb_bf16===false ? 'auto' : 'cuda'; else if(p&&!p.local_ok) $('#optDevice').value='auto';
  if(a) $('#optRemote').checked=!!a.needs_remote_code;
  await loadRuns(); updateHeader();
  if(!silent) go('abl');
}
$('#useRepo').onclick=()=>{ const repo=$('#repoInput').value.trim(); if(!repo) return; selectModel({repo, slug:slugOf(repo), preset:null, local:S.models.find(x=>x.slug===slugOf(repo))}); };

// ------------------------------------------------------------------ runs (per model)
async function loadRuns(keep){
  const all=await api('/runs'); S.runs = S.model ? all.filter(r=>r.slug===S.model.slug) : [];
  const running = S.pipe.running && S.pipe.run_id && S.runs.find(r=>r.id===S.pipe.run_id);
  if(!(keep && S.runs.find(r=>r.id===S.runId))) S.runId = running ? running.id : (S.runs[0]?.id||null);
  $('#runsBox').style.display = S.runs.length>1 ? '' : 'none';
  $('#runSel').innerHTML=S.runs.map(r=>`<option value="${r.id}">${r.id.replace('_',' ')} · ${r.status}${r.layer!=null?' · layer '+r.layer:''}${r.verdict?' · '+r.verdict:''}</option>`).join(''); $('#runSel').value=S.runId;
  await selectRun(S.runId);
}
async function selectRun(id){
  S.runId=id; $('#runSel').value=id;
  if(!id){ S.run=null; S.events=[]; S.ES={}; renderHero(); renderGuide(); renderRecorded(); updateHeader(); return; }
  S.run=await api('/runs/'+id); MARKERS=S.run.refusal_markers||MARKERS;
  const live = S.pipe.running && S.pipe.run_id===id;
  if(!live){ S.events=(await api(`/runs/${id}/events`)).events; S.ES=foldEvents(S.events); S.evNext=0; }
  scanRevealed=-1; renderHero(); renderGuide(); renderRecorded();
  if(S.run.scan){ $('#tryPrompts').value=S.run.scan.prompts.slice(0,4).join('\n'); const pre=[...S.run.scan.prompts.slice(0,5),'Explain how a TCP handshake works.','Write a haiku about the sea.'];
    $('#probePresets').innerHTML=$('#chatPresets').innerHTML=pre.map(p=>`<span class="chip">${esc(p)}</span>`).join('');
    $('#probePresets').querySelectorAll('.chip').forEach(c=>c.onclick=()=>$('#probePrompt').value=c.textContent); $('#chatPresets').querySelectorAll('.chip').forEach(c=>c.onclick=()=>$('#chatPrompt').value=c.textContent); }
  if(S.run.measure){ const [lo,hi]=S.run.measure.scan_range; $('#tryLayer').min=lo; $('#tryLayer').max=hi; }
  if(S.run.choice?.layer!=null){ $('#tryLayer').value=S.run.choice.layer; $('#tryLayerVal').textContent=S.run.choice.layer; }
  const names=chatNames(); $('#chatBaseLbl').textContent=names.base+' · original'; $('#chatAblLbl').textContent=names.abl+' · abliterated';
  updateHeader();
}
$('#runSel').onchange=e=>selectRun(e.target.value);
function chatNames(){ return S.run?.meta?.ollama || S.run?.ollama?.names || {base:(S.model?.slug||'glm-edge-4b-chat')+'-base', abl:(S.model?.slug||'glm-edge-4b-chat')+'-abl'}; }

// ------------------------------------------------------------------ events -> step state
function foldEvents(evs){
  const ES={};
  for(const e of evs){
    const st = ES[e.step] || (ES[e.step]={status:'pending', first:e.t, layers:[], progress:null});
    st.last=e.t;
    if(e.status==='start'){ st.status='running'; Object.assign(st, e); }
    else if(e.status==='progress'){ st.status='running'; st.progress=e; }
    else if(e.status==='layer'){ st.status='running'; st.layers.push(e); }
    else if(e.status==='baseline'){ st.status='running'; st.baseline=e; }
    else if(e.status==='waiting'){ st.status='waiting'; Object.assign(st, e); }
    else if(e.status==='done'){ st.status='done'; Object.assign(st, e); }
    else if(e.status==='error'||e.status==='stopped'){ ES._error=e; }
  }
  if(ES._error){ for(const k of Object.keys(ES)) if(ES[k].status==='running') ES[k].status='error'; }
  return ES;
}
function stepState(key){
  const st=S.ES[key]; const R=S.run;
  if(st && st.status && st.status!=='pending') return st.status;
  if(R){ if(['download','inspect','load','measure'].includes(key)) return R.measure?'done':'pending';
    if(key==='scan') return R.scan?'done':'pending'; if(key==='choose') return R.choice?.layer!=null?'done':'pending';
    if(key==='apply') return R.apply?'done':'pending'; if(key==='verify') return R.apply?.after?'done':'pending'; if(key==='validate') return R.validation?'done':'pending';
    if(key==='gguf'||key==='ollama') return R.ollama?'done':'pending'; }
  return 'pending';
}

// ------------------------------------------------------------------ hero
function renderHero(){
  const R=S.run, n=R?.model?.n_layers||S.model?.local?.arch?.n_layers||40, W=420, H=200, bw=W/n, sc=R?.measure?.scan_range||[0,-1], ch=R?.choice?.layer;
  let s=`<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="xMidYMid slice" style="width:100%;height:100%">`;
  for(let l=0;l<n;l++){ const sep=R?.measure?.separation_pct?.[l]||20, h=36+sep*1.4; s+=`<rect class="band ${l>=sc[0]&&l<=sc[1]?'scan':''} ${l===ch?'chosen':''}" x="${l*bw+1}" y="${(H-h)/2}" width="${Math.max(1,bw-2)}" height="${h}" rx="2"/>`; }
  for(let k=0;k<7;k++){ const yy=50+k*16+(k%2)*6, d=3.2+k*0.35; s+=`<circle class="pulse" r="2.2" cy="${yy}" cx="0"><animate attributeName="cx" from="-4" to="${W+4}" dur="${d}s" begin="${-k*0.9}s" repeatCount="indefinite"/><animate attributeName="opacity" values="0;1;1;0" keyTimes="0;0.1;0.9;1" dur="${d}s" begin="${-k*0.9}s" repeatCount="indefinite"/></circle>`; }
  s+=`<text x="6" y="${H-8}">layer 0</text><text x="${W-6}" y="${H-8}" text-anchor="end">layer ${n-1}</text>`;
  if(ch!=null) s+=`<text x="${ch*bw+bw/2}" y="14" text-anchor="middle" style="fill:var(--s3)">▼ ${ch}</text>`;
  $('#stream').innerHTML=s+'</svg>';
  const st = R ? [[R.choice.layer??'–','chosen layer',true],[R.scan?`${R.scan.n_base}→${R.apply?.n_after??'?'}`:'–',`refusals of ${R.config.n_inst_test||16}`],[R.validation?.verdict||R.meta?.status||'–','validation'],[R.validation?fmt(R.validation.kl,3):'–','KL on harmless'],[R.meta?.ollama?'ready':'–','in Ollama']] : [['–','no run yet for this model']];
  $('#heroStats').innerHTML=st.map(([v,l,a])=>`<div class="stat"><div class="v ${a?'accent':''}">${esc(v)}</div><div class="l">${l}</div></div>`).join('');
}

// ------------------------------------------------------------------ guide
let guideBuilt=false, scanRevealed=-1, scanTimer=null, sepTimer=null;
function renderGuide(){
  const g=$('#guide');
  if(!guideBuilt){ g.innerHTML=GUIDE.map((s,i)=>`<div class="gstep" id="g-${s.key}"><div class="ghead"><span class="gnum">${i+1}</span><h3>${s.title}</h3><span class="gstate badge ghost">pending</span><span class="gtime small"></span></div>
      <div class="gbody"><div class="gtext"><p>${s.plain}</p><p><b>Why it matters.</b> ${s.why}</p><p><b>What to look for.</b> ${s.look}</p></div><div class="glive" id="gl-${s.key}"></div>
      <details><summary>Under the hood</summary><p class="small">${s.hood}</p></details><details><summary>For GLM-5.x</summary><p class="small">${s.glm5}</p></details></div></div>`).join(''); guideBuilt=true; }
  document.querySelectorAll('#guide > .narr').forEach(x=>x.remove());
  let done=0;
  for(const s of GUIDE){ const st=stepState(s.key), el=$('#g-'+s.key); el.className='gstep st-'+st; const b=el.querySelector('.gstate'); b.textContent=st; b.className='gstate badge '+({done:'pass',running:'info',waiting:'warn',error:'fail'}[st]||'ghost'); if(st==='done') done++;
    const es=S.ES[s.key]; el.querySelector('.gtime').textContent = es&&es.first&&es.last&&st==='done'&&es.last>es.first ? `${Math.round(es.last-es.first)} s` : '';
    try{ RENDER[s.key]($('#gl-'+s.key), S.ES[s.key]||{}, S.run, st); }catch(e){ console.error(s.key, e); } }
  if(S.ES._error){ const e=S.ES._error, el=document.createElement('div'); el.className='narr'; el.style.borderLeftColor='var(--critical)'; el.innerHTML=`<b style="color:var(--critical)">The run stopped:</b> ${esc(e.message||e.status)} — details in the log.`; g.prepend(el); }
  const run=S.pipe.running && S.pipe.run_id===S.runId;
  $('#runBar').style.width = run ? (100*done/GUIDE.length)+'%' : (done===GUIDE.length?'100%':'0');
}
const RENDER = {
  download(el, es, R){ const m=S.model?.local; el.innerHTML = es.path||m ? `<div class="kv"><b>folder</b><span class="mono">${esc(es.path||m?.path||'')}</span><b>revision</b><span class="mono">${esc(es.revision||m?.copy_info?.revision||R?.model?.revision||'–')}</span>${es.total_gb?`<b>size</b><span>${es.total_gb} GB</span>`:''}${es.cached?`<b>status</b><span>already present</span>`:''}</div>` : '<span class="small">downloaded when you press Run</span>'; },
  inspect(el, es, R){ const a = es.family!==undefined ? es : (R?.model?.arch || S.model?.local?.arch); if(!a||a.family===undefined){ el.innerHTML='<span class="small">after the download</span>'; return; }
    el.innerHTML=`<div class="stats">${[[a.family||a.model_type,'family',true],[a.n_layers,'layers'],[a.hidden_size,'hidden size'],[a.params_b?a.params_b+'B':'?','parameters'],[`<span class="badge ${a.support==='exact'?'pass':(a.support==='unsupported'?'fail':'info')}">${a.support}</span>`,'edit']].map(([v,l,ac])=>`<div class="stat"><div class="v ${ac?'accent':''}" style="font-size:18px">${v}</div><div class="l">${l}</div></div>`).join('')}</div>
      <div class="kv"><b>architecture</b><span class="mono">${esc((a.architectures||[]).join(', '))}</span><b>MoE</b><span>${a.moe?`${a.moe_info?.n_routed_experts} routed + ${a.moe_info?.n_shared_experts||0} shared experts, ${a.moe_info?.num_experts_per_tok} active, first ${a.moe_info?.first_k_dense_replace??0} layers dense`:'no (dense)'}</span><b>post-norm</b><span>${a.post_norm?'yes - direction folded through the norm weight':'no - exact edit'}</span><b>quantized</b><span>${a.quantization?esc(JSON.stringify(a.quantization)):'no (bf16)'}</span><b>targets in index</b><span class="mono">${esc(JSON.stringify(a.tensor_kinds||{}))}</span></div>
      ${(a.notes||[]).map(n=>`<div class="narr small">${esc(n)}</div>`).join('')}`; },
  load(el, es, R){ el.innerHTML = es.n_layers ? `<div class="kv"><b>loaded</b><span>${es.n_layers} layers, d_model ${es.d_model}, ${esc(es.dtype||'')} on ${esc(es.device_map||'')}</span></div>` : (R?.measure?`<div class="kv"><b>loaded</b><span>${R.model.n_layers} layers, d_model ${R.model.d_model}</span></div>`:''); },
  measure(el, es, R, st){
    if(st==='running'&&es.progress){ const p=es.progress; el.innerHTML=`<div class="narr">Measuring the <b>${p.group}</b> group: batch ${p.batch}/${p.batches} (${p.seconds}s each)</div><div class="progress"><i style="width:${100*p.batch/p.batches}%"></i></div>`; return; }
    const M=R?.measure; const sep = M?.separation_pct || es.separation_pct; if(!sep){ el.innerHTML=st==='running'?'<div class="narr">starting…</div>':''; return; }
    const peak=M?.peak??es.peak, stable=M?.stable||es.stable||[], [lo,hi]=M?.scan_range||es.scan_range||[0,sep.length-1], NL=sep.length;
    el.innerHTML=`<div class="row"><button class="btn sm primary" id="playSep">▶ play through the layers</button><span class="small">or click a bar</span></div><div class="narr" id="narrSep">Strongest separation in <b>layer ${peak}</b>; layers <b>${stable[0]}–${stable[stable.length-1]}</b> share almost the same direction. Scan range ${lo}–${hi}.</div><div id="chartSep"></div>
      <div class="legend"><span style="--c:var(--s1)">scanned next</span><span style="--c:var(--grid)">not scanned</span></div>${M?`<details><summary>Direction stability (cosine similarity between layers)</summary><div class="grid2" style="margin-top:8px"><div id="chartSim"></div><div id="chartNext"></div></div></details>`:''}`;
    let shown=-1, sel=null;
    const draw=()=>barChart($('#chartSep'), sep.map((v,i)=>(shown<0||i<=shown)?v:0), {max:Math.max(...sep)*1.15, cls:i=>(i<lo||i>hi?'out ':'')+(i===sel?'sel':''), labelIdx:[peak], fmtY:v=>fmt(v,0)+'%', xlabel:'layer (0 = input)', ylabel:'difference, % of activation', tip:i=>`layer ${i}: ${fmt(sep[i],1)}%${M?` · raw ${fmt(M.norms[i],2)} / act ${fmt(M.act_size[i],0)}`:''}`, click:i=>{ clearInterval(sepTimer); sel=i; shown=-1; $('#narrSep').innerHTML=`<b>Layer ${i}</b>: harmful and harmless means differ by <b>${fmt(sep[i],1)}%</b> of the activation size${i===peak?' — the strongest separation':''}. ${i<lo?'Before the scan range.':(i>hi?'After the scan range.':'Inside the scan range.')}`; draw(); }});
    $('#playSep').onclick=()=>{ clearInterval(sepTimer); shown=0; sel=null; draw(); sepTimer=setInterval(()=>{ shown++; if(shown>=NL){ clearInterval(sepTimer); shown=-1; draw(); return; } $('#narrSep').innerHTML=`<b>Layer ${shown}</b>: ${fmt(sep[shown],1)}% ${shown<lo?'(too early to scan)':(shown>hi?'(too late to scan)':'')}`; draw(); },250); };
    draw(); if(M){ heatmap($('#chartSim'), M.similarity, M.stable); const nx=M.cos_next.slice(0,-1); barChart($('#chartNext'), nx, {max:1.05, height:230, ticks:2, fmtY:v=>fmt(v,1), xlabel:'layer L vs L+1', ylabel:'cosine', cls:i=>(i<lo||i>hi?'out':''), tip:i=>`layer ${i} vs ${i+1}: ${fmt(nx[i],3)}`}); }
  },
  scan(el, es, R, st){
    const SC=R?.scan; const live = st==='running';
    const layers = SC ? SC.layers.map(l=>l.layer).sort((a,b)=>a-b) : (es.layers||[]).map(e=>e.layer);
    const by = SC ? Object.fromEntries(SC.layers.map(l=>[l.layer,l])) : Object.fromEntries((es.layers||[]).map(e=>[e.layer,e]));
    const prompts = SC?.prompts || null, baseline = SC?.baseline || es.baseline?.baseline, n_base = SC?.n_base ?? es.baseline?.n_base, NT = SC?.prompts.length ?? es.baseline?.n_test ?? es.n_test ?? 16;
    if(!layers.length && n_base==null){ el.innerHTML = live?'<div class="narr">generating the baseline…</div>':''; return; }
    const allLayers = es.layers_planned || (R?.measure ? Array.from({length:R.measure.scan_range[1]-R.measure.scan_range[0]+1},(_,i)=>R.measure.scan_range[0]+i) : layers);
    const chosen=R?.choice?.layer;
    if(live || !SC){
      const last = layers.length ? by[layers[layers.length-1]] : null;
      el.innerHTML=`<div class="narr">Baseline: <b>${n_base}/${NT}</b> refusals. ${layers.length?`Tested ${layers.length}/${allLayers.length} layers; last: layer <b>${last.layer}</b> → <b>${last.refusals}/${NT}</b> refusals${last.cjk_ratio>0.2?' (mostly Chinese!)':''}.`:'Scanning the first layer…'}</div><div id="chartScan"></div><div class="legend"><span style="--c:var(--s1)">refusals with this layer's direction removed</span><span style="--c:var(--s2)">mostly Chinese</span><span style="--c:var(--muted)">— baseline</span></div>
        ${last?`<div class="prompt" style="margin-top:12px">latest answer (layer ${last.layer}) to: ${esc(prompts?prompts[0]:'the first test prompt')}</div><div class="pair">${answerBox('untouched', baseline?baseline[0]:'')}${answerBox(`layer ${last.layer} removed`, last.generations[0])}</div>`:''}`;
      barChart($('#chartScan'), allLayers.map(l=>by[l]?by[l].refusals:null), {max:NT+1, ticks:Math.min(NT,8), height:220, xlab:i=>allLayers[i], cls:i=>(by[allLayers[i]]?.cjk_ratio>0.2?'cjk':''), hline:n_base, hlineLabel:`baseline ${n_base}/${NT}`, xlabel:'layer the direction was taken from', ylabel:`refusals of ${NT}`, tip:i=>{const r=by[allLayers[i]]; return r?`layer ${r.layer}: ${r.refusals}/${NT} · Chinese ${fmt(r.cjk_ratio*100,0)}%`:`layer ${allLayers[i]}: pending`;}});
      return;
    }
    el.innerHTML=`<div class="row"><button class="btn sm primary" id="nextScan">Next layer ▶</button><button class="btn sm" id="playScan">▶ play all</button><button class="btn sm" id="resetScan">reset</button><label class="small">layer <input type="range" id="scanSlider" min="0" max="${layers.length-1}" value="0"> <b class="mono" id="scanLbl"></b></label></div>
      <div class="narr" id="narrScan"></div><div class="layers" id="strip"></div><div id="chartScan"></div><div class="legend"><span style="--c:var(--s1)">refusals with this layer's direction removed</span><span style="--c:var(--s2)">mostly Chinese</span><span style="--c:var(--s3)">chosen layer</span><span style="--c:var(--muted)">— baseline</span></div>
      <details id="gensWrap"><summary id="genTitle">answers</summary><p class="small">Left: untouched model. Right: the selected layer's direction removed. Refusal phrases are <mark>highlighted</mark>.</p><div id="gens"></div></details>`;
    const NL=R.model.n_layers;
    const draw=()=>{
      $('#strip').innerHTML=Array.from({length:NL},(_,l)=>{ const i=layers.indexOf(l); return `<div class="${i>=0&&i<=scanRevealed?'on':''} ${i===scanRevealed?'now':''}">${l}</div>`; }).join('');
      barChart($('#chartScan'), layers.map((l,i)=>i<=scanRevealed?by[l].refusals:null), {max:NT+1, ticks:Math.min(NT,8), height:220, xlab:i=>layers[i], cls:i=>(layers[i]===chosen?'chosen':(by[layers[i]].cjk_ratio>0.2?'cjk':''))+(i===scanRevealed?' sel':''), hline:n_base, hlineLabel:`baseline ${n_base}/${NT}`, xlabel:'layer the direction was taken from', ylabel:`refusals of ${NT}`, tip:i=>{const r=by[layers[i]]; return `layer ${layers[i]}: ${r.refusals}/${NT} · Chinese ${fmt(r.cjk_ratio*100,0)}%\n${(r.generations[0]||'').slice(0,90)}…`;}, click:i=>{ clearInterval(scanTimer); scanRevealed=i; $('#scanSlider').value=i; draw(); }});
      if(scanRevealed<0){ $('#narrScan').innerHTML=`<b>Baseline</b>: nothing removed, <b>${n_base}/${NT}</b> refusals. Click <b>Next layer</b> to test layer ${layers[0]}.`; $('#genTitle').textContent=`baseline answers — ${n_base}/${NT} refusals`; $('#scanLbl').textContent='baseline';
        $('#gens').innerHTML=prompts.map((p,i)=>`<div class="prompt"><span class="i">${String(i+1).padStart(2,'0')}</span>${esc(p)}</div><div class="pair">${answerBox('untouched', baseline[i])}<div class="ans small" style="display:grid;place-items:center">pick a layer</div></div>`).join(''); return; }
      const l=layers[scanRevealed], r=by[l], best=Math.min(...layers.slice(0,scanRevealed+1).map(x=>by[x].refusals)); $('#scanLbl').textContent=l;
      $('#narrScan').innerHTML=`<b>Layer ${l}</b>: <b>${r.refusals}/${NT}</b> refusals left (baseline ${n_base}). ${r.cjk_ratio>0.2?'<b>Warning:</b> answers are largely Chinese. ':''}${r.refusals===best?'Best so far. ':''}${l===chosen?'<b>This is the applied layer.</b> ':''}Open the answers: on topic and coherent?`;
      $('#genTitle').textContent=`answers with layer ${l} removed — ${r.refusals}/${NT} refusals`;
      $('#gens').innerHTML=pairs(prompts, baseline, r.generations, 'untouched', `layer ${l} removed`);
    };
    $('#nextScan').onclick=()=>{ clearInterval(scanTimer); if(scanRevealed<layers.length-1){ scanRevealed++; $('#scanSlider').value=scanRevealed; draw(); } };
    $('#resetScan').onclick=()=>{ clearInterval(scanTimer); scanRevealed=-1; $('#scanSlider').value=0; draw(); };
    $('#playScan').onclick=()=>{ clearInterval(scanTimer); scanRevealed=-1; draw(); scanTimer=setInterval(()=>{ if(scanRevealed>=layers.length-1){ clearInterval(scanTimer); return; } scanRevealed++; $('#scanSlider').value=scanRevealed; draw(); },1200); };
    $('#scanSlider').oninput=e=>{ clearInterval(scanTimer); scanRevealed=+e.target.value; draw(); };
    if(scanRevealed>layers.length-1) scanRevealed=layers.length-1; draw();
  },
  choose(el, es, R, st){
    const SC=R?.scan; const rec = es.recommended ?? R?.meta?.recommended; const layer = es.layer ?? R?.choice?.layer;
    if(st==='waiting'){ el.innerHTML=`<div class="narr">The run is <b>paused</b>. Recommended by the rule: <b>layer ${rec}</b>. Read the answers in the scan above, then continue.</div><div class="row"><label>layer <input type="number" id="chooseLayer" value="${rec}" min="0" max="${(R?.model?.n_layers||40)-1}" style="width:80px"></label><button class="btn primary" id="continueBtn">▶ Continue with this layer</button></div>`;
      $('#continueBtn').onclick=async()=>{ try{ await api('/pipeline/start', {engine:'abliterate', stage:'continue', run_id:S.runId, layer:+$('#chooseLayer').value, no_ollama:!$('#optOllama').checked, skip_verify:!$('#optVerify').checked, device_map:$('#optDevice').value}); S.evNext=0; toast('continuing'); }catch(e){ toast(e.message, true); } }; return; }
    if(layer==null){ el.innerHTML = st==='running'?'<div class="narr">choosing…</div>':''; return; }
    const sorted = SC ? [...SC.layers].sort((a,b)=>a.layer-b.layer) : [];
    el.innerHTML=`<div class="narr">Chosen: <b>layer ${layer}</b>${es.by?` (${es.by==='user'?'picked by you':'by the rule'})`:''}${rec!=null&&rec!==layer?`; the rule would have picked ${rec}`:''}.</div>` + (sorted.length?`<details><summary>All scanned layers</summary><table><tr><th>layer</th><th class="num">refusals</th><th class="num">Chinese</th><th>first answer</th></tr>${sorted.map(s=>`<tr class="${s.layer===layer?'chosen':''}"><td class="mono">${s.layer}</td><td class="num">${s.refusals}/${SC.prompts.length}</td><td class="num">${fmt(s.cjk_ratio*100,0)}%</td><td class="small">${esc((s.generations[0]||'').slice(0,100))}…</td></tr>`).join('')}</table></details>`:'');
  },
  apply(el, es, R, st){
    if(st==='running'&&es.progress){ const p=es.progress; el.innerHTML=`<div class="narr">Editing shard ${p.shard}/${p.shards} (${p.seconds}s per shard)</div><div class="progress"><i style="width:${100*p.shard/p.shards}%"></i></div>`; return; }
    const a = es.n_changed!=null ? es : (R?.apply?.stats || null); const o=R?.apply?.orthogonality;
    if(!a && !o){ el.innerHTML = st==='running'?'<div class="narr">starting the edit…</div>':''; return; }
    const ex=v=>v==null?'–':Number(v).toExponential(1);
    el.innerHTML=`<div class="formula">W′ = W − r rᵀ W</div><div class="stats">${[[a?.n_changed??R?.apply?.changed_tensors??'–','tensors changed'],[a?.kinds?`${a.kinds.embed||0} / ${a.kinds.attn_out||0} / ${a.kinds.mlp_out||0}`:'–','embed / attn out / mlp out'],[ex(a?.max_rw ?? Math.max(o?.embed_tokens||0,o?.o_proj||0,o?.down_proj||0)),'max |r·W′| after'],[a?.fp8??0,'FP8 tensors requantized'],[a?.folded??0,'post-norm folds'],[a?.seconds!=null?a.seconds+' s':'–','time']].map(([v,l])=>`<div class="stat"><div class="v" style="font-size:18px">${v}</div><div class="l">${l}</div></div>`).join('')}</div>`;
  },
  verify(el, es, R, st){
    const after = es.after || R?.apply?.after; const SC=R?.scan; if(!after){ el.innerHTML=st==='running'?'<div class="narr">reloading the edited model…</div>':''; return; }
    const n_after = es.n_after ?? R?.apply?.n_after, sc = es.scan_refusals ?? R?.choice?.refusals_in_scan;
    el.innerHTML=`<div class="narr">After the permanent edit: <b>${n_after}/${after.length}</b> refusals without hooks${sc!=null?` (scan said ${sc})`:''}.</div>${SC?`<details><summary>answers after the edit</summary>${pairs(SC.prompts, SC.baseline, after, 'base model', 'abliterated weights')}</details>`:''}`;
  },
  validate(el, es, R, st){
    if(st==='running'&&es.progress){ el.innerHTML=`<div class="narr">${esc(es.progress.stage)}…</div>`; return; }
    const v = es.checks ? es : R?.validation; if(!v){ el.innerHTML=''; return; }
    const h=R?.validation?.harmless;
    el.innerHTML=`<div class="stats"><div class="stat"><div class="v">${statusBadge(v.verdict)}</div><div class="l">overall</div></div><div class="stat"><div class="v">${fmt(v.kl,3)}</div><div class="l">KL on harmless</div></div></div><table><tr><th>check</th><th>result</th><th>status</th><th>why</th></tr>${v.checks.map(c=>`<tr><td>${esc(c.check)}</td><td class="mono">${esc(c.result)}</td><td>${statusBadge(c.status)}</td><td class="small">${esc(c.why)}</td></tr>`).join('')}</table>${h&&h.prompts.length?`<details><summary>harmless prompts, base vs abliterated</summary>${pairs(h.prompts,h.base,h.abl,'base','abliterated',6)}</details>`:''}`;
  },
  gguf(el, es, R, st){ el.innerHTML = es.base ? `<div class="kv"><b>base</b><span class="mono">${esc(es.base)}</span><b>abliterated</b><span class="mono">${esc(es.abl)}</span></div>` : (st==='running'?`<div class="narr">converting${es.progress?.which?` (${es.progress.which} done)`:''}…</div>`:''); },
  ollama(el, es, R, st){
    const o=R?.ollama; const names = es.names || o?.names || R?.meta?.ollama;
    if(st==='running'){ el.innerHTML=`<div class="narr">importing${es.progress?.created?` (${es.progress.created} created)`:''}…</div>`; return; }
    if(!o && es.n_ref_base==null){ el.innerHTML=''; return; }
    const nb=es.n_ref_base??o?.n_ref_base, na=es.n_ref_abl??o?.n_ref_abl, nh=o?.harmful?.length??10;
    el.innerHTML=`<div class="stats"><div class="stat"><div class="v">${nb}/${nh}</div><div class="l">base refusals</div></div><div class="stat"><div class="v accent">${na}/${nh}</div><div class="l">abliterated refusals</div></div></div><div class="kv"><b>Ollama models</b><span class="mono">${names?`${names.base} · ${names.abl}`:'–'}</span></div><div class="row"><button class="btn sm primary" onclick="go('compare')">Compare before vs after →</button></div>`;
  },
};
function recordedHtml(){ const o=S.run?.ollama; if(!o) return ''; const all=[...o.harmful,...o.normal]; return all.map((p,i)=>o.results.base[i]==null?'':`<div class="prompt"><span class="i">${i<o.harmful.length?'harmful':'normal'}</span>${esc(p)}</div><div class="pair">${answerBox('original',o.results.base[i])}${answerBox('abliterated',o.results.abl[i])}</div>`).join(''); }
function renderRecorded(){ const o=S.run?.ollama; $('#chatRecordedBody').innerHTML = o?`<p class="small">Refusals via Ollama: original ${o.n_ref_base}/${o.harmful.length}, abliterated ${o.n_ref_abl}/${o.harmful.length}.</p>${recordedHtml()}`:''; $('#chatRecorded').style.display=o?'':'none'; }

// ------------------------------------------------------------------ run control
$('#runBtn').onclick=async()=>{
  if(!S.model) return toast('pick a model first', true);
  const body={engine:'abliterate', stage:'all', model:S.model.repo, pause_at_choice:$('#optPause').checked, no_ollama:!$('#optOllama').checked, skip_verify:!$('#optVerify').checked, device_map:$('#optDevice').value,
    n_train:+$('#optTrain').value, n_test:+$('#optTest').value, layer_range:$('#optRange').value, max_new_tokens:+$('#optTokens').value, batch:+$('#optBatch').value, gen_batch:+$('#optGenBatch').value, trust_remote_code:$('#optRemote').checked};
  try{ await api('/pipeline/start', body); S.ES={}; S.events=[]; S.evNext=0; S.logNext=0; $('#console').innerHTML=''; S.runId=null; S.run=null; renderHero(); renderGuide(); updateHeader(); toast('run started'); }catch(e){ toast(e.message, true); }
};
$('#stopBtn').onclick=$('#pipeStop').onclick=async()=>{ await api('/pipeline/stop', {}); toast('stopped'); };
$('#ollUnload').onclick=async()=>{ const r=await api('/ollama/unload', {}); toast('unloaded: '+(r.unloaded.join(', ')||'nothing')); loadEnv(); };

async function pollPipeline(){
  try{
    const st=await api('/pipeline/status'); const was=S.pipe.running; S.pipe=st;
    $('#dotPipe').className='dot '+(st.running?'busy':(st.exit_code===0?'on':(st.exit_code!=null?'bad':'')));
    $('#sysPipe').textContent = st.running ? `${st.stage} ${Math.floor(st.elapsed_s/60)}:${String(st.elapsed_s%60).padStart(2,'0')}` : 'idle';
    $('#runBtn').disabled=st.running; $('#stopBtn').disabled=$('#pipeStop').disabled=!st.running;
    $('#runInfo').textContent = st.running ? `${st.stage} · ${st.current||'starting'}` : (st.stage?`last: ${st.stage}, exit ${st.exit_code}`:'');
    $('#pipeInfo').textContent = $('#runInfo').textContent;
    if(st.n_lines < S.logNext){ S.logNext=0; $('#console').innerHTML=''; }
    if(st.n_lines > S.logNext){ const lg=await api(`/pipeline/log?start=${S.logNext}`); S.logNext=lg.next; appendLog(lg.lines); }
    if(st.engine==='abliterate' && st.run_id){
      if(st.running && S.runId!==st.run_id){ await loadRuns(false); if(S.runId!==st.run_id){ /* run of another model: switch model */ const all=await api('/runs'); const r=all.find(x=>x.id===st.run_id); if(r){ await loadModels(); const e=S.models.find(x=>x.slug===r.slug); if(e) await selectModel({repo:e.copy_info?.repo||e.slug, slug:e.slug, preset:S.presets.find(p=>slugOf(p.repo)===e.slug)||null, local:e}, true); } } S.ES={}; S.events=[]; S.evNext=0; }
      if(st.run_id===S.runId && (st.running || st.n_events>S.evNext)){
        if(st.n_events < S.evNext){ S.evNext=0; S.events=[]; }
        if(st.n_events > S.evNext){ const ev=await api(`/pipeline/events?start=${S.evNext}`); S.evNext=ev.next; S.events.push(...ev.events); S.ES=foldEvents(S.events);
          if(ev.events.some(e=>['done','waiting','error'].includes(e.status)&&['measure','scan','choose','apply','verify','validate','ollama','done','error'].includes(e.step))) S.run=await api('/runs/'+S.runId);
          if(ev.events.some(e=>e.step==='download'&&e.status==='done')) loadModels();
          renderHero(); renderGuide(); updateHeader(); } }
    }
    if(was && !st.running){ toast(`${st.stage} finished (exit ${st.exit_code})`, st.exit_code!==0); await loadModels(); await loadRuns(true); loadEnv(); }
    updateHeader();
  }catch(e){ console.error(e); }
}
function appendLog(lines){ const c=$('#console'); if(c.textContent.startsWith('— no output')) c.innerHTML='';
  for(const l of lines){ const cls = l.startsWith('EVENT') ? 'hl' : (/ERROR|FAILED|Traceback|Error:/.test(l)?'err':(/PASS|done$|OK:/.test(l)?'ok':'')); const d=document.createElement('div'); if(cls) d.className=cls; d.textContent=l; c.appendChild(d); }
  while(c.children.length>800) c.removeChild(c.firstChild); c.scrollTop=c.scrollHeight; }

// ------------------------------------------------------------------ lab
async function labStatus(){ try{ S.lab=await api('/lab/status'); }catch(e){ return; } const l=S.lab;
  const mem = l.vram_total_gb!=null ? ` · VRAM free ${l.vram_free_gb}/${l.vram_total_gb} GB` : (S.env?.cuda===false ? ' · on the CPU' : '');
  $('#labInfo').innerHTML = l.loaded ? `resident since ${l.loaded_at} · <span class="mono">${esc((l.model_dir||'').split(/[\\/]/).pop())}</span>${mem}` : `not loaded${mem}`;
  $('#labLoad').disabled=!!l.busy; $('#probeBtn').disabled=$('#tryBtn').disabled=!l.loaded||!!l.busy; }
$('#labLoad').onclick=async()=>{ if(!S.runId) return toast('no run for this model yet', true); if(!S.run?.measure) return toast('this run has no measured directions yet', true); $('#labInfo').textContent=S.env?.cuda===false?'loading on the CPU (a minute or two)…':'loading (~30 s)…'; $('#labLoad').disabled=true; try{ await api('/lab/load', {run_id:S.runId}); toast('model resident'); }catch(e){ toast(e.message, true); } labStatus(); loadEnv(); };
$('#labUnload').onclick=async()=>{ await api('/lab/unload', {}); labStatus(); loadEnv(); };
$('#probeBtn').onclick=async()=>{ const prompt=$('#probePrompt').value.trim(); if(!prompt) return; $('#probeInfo').textContent='probing…'; $('#probeBtn').disabled=true;
  try{ const r=await api('/lab/probe', {prompt}); const NL=r.layers.length, sc=S.run?.measure?.scan_range||[0,NL-1], score=r.layers.map(x=>x.score);
    $('#probeOut').innerHTML=`<div class="narr">${Math.round(r.refusal_like*100)}% of layers read this prompt as <b>harmful-like</b> (score &gt; 0.5). Peak layers: <b>${r.top_layers.join(', ')}</b>. 0 = like the harmless mean, 1 = like the harmful mean.</div><div id="probeChart"></div><div class="legend"><span style="--c:var(--s1)">score per layer (shade = strength)</span><span style="--c:var(--grid)">outside the scan range</span></div><h3 style="margin-top:16px">Token by token <small>projection onto the direction of the peak layers</small></h3><div id="probeTrace"></div><div class="tokens">${r.tokens.map(t=>`<span class="tok">${esc(t)}</span>`).join('')}</div>`;
    barChart($('#probeChart'), score.map(v=>Math.max(-0.2,Math.min(1.3,v))+0.2), {max:1.5, ticks:3, height:220, fmtY:v=>fmt(v-0.2,1), xlabel:'layer', ylabel:'refusal score', cls:i=>(i<sc[0]||i>sc[1]?'out':''), fill:i=>(i<sc[0]||i>sc[1])?null:`color-mix(in srgb, var(--s1) ${Math.round(Math.max(0.15,Math.min(1,score[i]))*100)}%, var(--surface2))`, tip:i=>{const x=r.layers[i]; return `layer ${i}\nscore ${fmt(x.score,2)} · cos ${fmt(x.cos,3)}\nprojection ${fmt(x.proj,1)} (harmless ${fmt(x.ref_harmless,1)}, harmful ${fmt(x.ref_harmful,1)})`;}});
    const cols=['var(--s1)','var(--s5)','var(--s3)'], skip=Math.min(3, r.tokens.length-2);
    lineChart($('#probeTrace'), Object.entries(r.traces).map(([l,v],k)=>({name:`layer ${l}`, values:v.slice(skip), color:cols[k%3]})), r.tokens.slice(skip), {ylabel:'projection on r'});
    $('#probeInfo').innerHTML=Object.keys(r.traces).map((l,k)=>`<span class="legend"><span style="--c:${cols[k%3]}">layer ${l}</span></span>`).join(' ');
  }catch(e){ toast(e.message, true); $('#probeInfo').textContent=''; } labStatus(); };
$('#tryLayer').oninput=e=>$('#tryLayerVal').textContent=e.target.value;
$('#tryBtn').onclick=async()=>{ const prompts=$('#tryPrompts').value.split('\n').map(x=>x.trim()).filter(Boolean).slice(0,8); if(!prompts.length) return; const layer=+$('#tryLayer').value; $('#tryInfo').textContent=`generating with layer ${layer} removed…`; $('#tryBtn').disabled=true;
  try{ const r=await api('/lab/try', {layer, prompts, max_new_tokens:+$('#tryTokens').value}); $('#tryOut').innerHTML=`<div class="narr">Layer <b>${layer}</b>: <b>${r.n_abl}/${prompts.length}</b> refusals with the direction removed, <b>${r.n_base}/${prompts.length}</b> without.</div>`+pairs(prompts, r.baseline, r.ablated, 'untouched', `layer ${layer} removed`); $('#tryInfo').textContent=''; }
  catch(e){ toast(e.message, true); $('#tryInfo').textContent=''; } labStatus(); };

// ------------------------------------------------------------------ chat
async function chatStatus(){ const names=chatNames(); try{ const j=await api('/ollama/tags'); const have=(j.models||[]).map(m=>m.name); const miss=[names.base,names.abl].filter(n=>!have.includes(n)&&!have.includes(n+':latest'));
  $('#chatStatus').innerHTML = miss.length? `<span class="badge warn">missing in Ollama</span> ${miss.join(', ')}` : `<span class="badge pass">ready</span> ${names.base} and ${names.abl}`; }catch(e){ $('#chatStatus').innerHTML='<span class="badge fail">Ollama not reachable</span>'; } }
let ctrl=null;
async function ask(model, box, badgeEl, prompt){ const t=box.querySelector('.t'); t.textContent=''; badgeEl.innerHTML='';
  const res=await fetch('/api/ollama/chat', {method:'POST', signal:ctrl.signal, headers:{'Content-Type':'application/json'}, body:JSON.stringify({model, prompt, num_predict:+$('#chatTokens').value||300})});
  if(!res.ok) throw new Error(`${model}: HTTP ${res.status}`);
  const rd=res.body.getReader(), dec=new TextDecoder(); let buf='', full='';
  while(true){ const {value,done}=await rd.read(); if(done) break; buf+=dec.decode(value,{stream:true}); let i; while((i=buf.indexOf('\n'))>=0){ const line=buf.slice(0,i); buf=buf.slice(i+1); if(!line.trim()) continue; try{ const j=JSON.parse(line); full+=j.message?.content||''; t.innerHTML=highlight(full); badgeEl.innerHTML=badge(full); }catch(e){} } }
  return full; }
$('#chatSend').onclick=async()=>{ const prompt=$('#chatPrompt').value.trim(); if(!prompt) return; const names=chatNames(); ctrl=new AbortController(); $('#chatSend').disabled=true; $('#chatStop').disabled=false;
  try{ const [b,a]=await Promise.all([ask(names.base,$('#chatBase'),$('#chatBaseBadge'),prompt), ask(names.abl,$('#chatAbl'),$('#chatAblBadge'),prompt)]); S.chatHist.unshift({prompt,b,a}); $('#chatHistBody').innerHTML=S.chatHist.slice(1).map(h=>`<div class="prompt">${esc(h.prompt)}</div><div class="pair">${answerBox('original',h.b)}${answerBox('abliterated',h.a)}</div>`).join('')||'none yet'; }
  catch(e){ if(e.name!=='AbortError') $('#chatBase .t').textContent='Error: '+e.message; }
  $('#chatSend').disabled=false; $('#chatStop').disabled=true; loadEnv(); };
$('#chatStop').onclick=()=>ctrl&&ctrl.abort();

// ------------------------------------------------------------------ boot
(async function boot(){
  await loadEnv(); await pollPipeline(); await loadModels(); await labStatus();
  const h=location.hash.slice(1);
  if(h==='compare' && cmpReady()) go('compare'); else if(h==='abl' && S.model) go('abl'); else if(S.pipe.running && S.model) go('abl'); else go('model');
  setInterval(pollPipeline, 2000); setInterval(loadEnv, 8000); setInterval(labStatus, 5000);
})();

// ================================================================== datasets panel
const DS = { file:'harmful_train.jsonl', q:'', regex:false, source:'', offset:0, limit:40, status:[], sel:new Set(), last:null };
$('#dataToggle').onclick=()=>{ $('#dataPanel').classList.add('open'); $('#sbomPanel').classList.remove('open'); $('#servePanel').classList.remove('open'); dataLoad(); };
$('#dataClose').onclick=()=>$('#dataPanel').classList.remove('open');
async function dataLoad(){ DS.status=await api('/data'); $('#dataTabs').innerHTML=DS.status.map(f=>`<button class="${f.file===DS.file?'active':''}" data-f="${f.file}">${esc(f.label)} <span class="mono">${f.rows_now}</span>${f.edited?' ✎':''}</button>`).join('');
  $('#dataTabs').querySelectorAll('button').forEach(b=>b.onclick=()=>{ DS.file=b.dataset.f; DS.offset=0; DS.source=''; DS.sel.clear(); dataLoad(); });
  const f=DS.status.find(x=>x.file===DS.file); $('#dataMeta').innerHTML=`<div class="kv"><b>file</b><span class="mono">data/${f.file}</span><b>source</b><span class="mono">${esc(f.repo)} @ ${f.requested?esc(f.requested)+' = ':''}${esc((f.revision||'').slice(0,8))}${f.column?' · column '+esc(f.column):''} · exported ${esc(f.exported||'')}</span>${f.absent?`<b>note</b><span>${esc(f.repo)} has no such split: the held-out prompts come from the end of harmful · train</span>`:''}<b>used for</b><span>${esc(f.used)}</span><b>rows</b><span>${f.absent?'none in the source':(f.rows_original??'?')+' original'} · ${f.rows_now} now · ${f.removed} removed · ${f.edited?'<span class="badge warn">edited</span>':'<span class="badge pass">unchanged</span>'} · ${f.size_mb} MB</span></div>`;
  $('#dataAddBox').innerHTML = f.kind==='prompt' ? `<div class="row"><input type="text" id="addPrompt" placeholder="new prompt" style="max-width:600px"><button class="btn sm" id="addBtn">add</button></div>` : `<div class="row"><input type="text" id="addPrompt" placeholder="user prompt"><input type="text" id="addChosen" placeholder="chosen answer"><input type="text" id="addRejected" placeholder="rejected answer"><input type="text" id="addSource" placeholder="source" style="max-width:140px"><button class="btn sm" id="addBtn">add</button></div>`;
  $('#addBtn').onclick=async()=>{ const pr=$('#addPrompt').value.trim(); if(!pr) return; const body = f.kind==='prompt' ? {prompt:pr} : {source:$('#addSource').value||'app', chosen:[{role:'user',content:pr},{role:'assistant',content:$('#addChosen').value}], rejected:[{role:'user',content:pr},{role:'assistant',content:$('#addRejected').value}]};
    try{ await api(`/data/${DS.file}/rows`, body); toast('row added'); dataLoad(); }catch(e){ toast(e.message,true); } };
  await dataSearch(); dataRemoved();
}
async function dataSearch(){ DS.q=$('#dataQ').value; DS.regex=$('#dataRegex').checked;
  try{ const r=await api(`/data/${DS.file}?q=${encodeURIComponent(DS.q)}&offset=${DS.offset}&limit=${DS.limit}&regex=${DS.regex}${DS.source?'&source='+encodeURIComponent(DS.source):''}`); DS.last=r;
    $('#dataCount').textContent=`${r.matches} of ${r.total} rows${DS.q?' match':''}`; $('#dataPage').textContent=`${r.offset+1}–${Math.min(r.offset+r.limit,r.matches)}`;
    const srcSel=$('#dataSource'); if(r.sources){ srcSel.style.display=''; srcSel.innerHTML='<option value="">all sources</option>'+r.sources.map(([s,n])=>`<option value="${esc(s)}" ${s===DS.source?'selected':''}>${esc(s)} (${n})</option>`).join(''); } else srcSel.style.display='none';
    const kind=DS.status.find(x=>x.file===DS.file).kind;
    $('#dataRows').innerHTML = r.rows.map(row=>{ const id=row.id; const pr = kind==='prompt' ? row.prompt : (row.chosen?.[0]?.content||''); const chosen=row.chosen?.slice(1).map(m=>m.content).join('\n')||'', rejected=row.rejected?.slice(1).map(m=>m.content).join('\n')||'';
      return `<div class="rowbox" data-id="${esc(id)}"><div class="row" style="margin:0;justify-content:space-between"><span><input type="checkbox" class="selrow" ${DS.sel.has(id)?'checked':''}> <span class="id">${esc(id)}${row.source?' · '+esc(row.source):''}${row.edited_at?' · edited':''}${row.added_by?' · added':''}</span></span><span class="acts"><button class="btn sm editrow">edit</button><button class="btn sm danger delrow">remove</button></span></div><div class="txt">${highlightQ(pr)}</div>${kind==='dpo'?`<div class="dpo"><div><b>chosen (trained in)</b>${highlightQ(chosen)}</div><div><b>rejected</b>${highlightQ(rejected)}</div></div>`:''}</div>`; }).join('') || '<div class="empty">no rows</div>';
    $('#dataRows').querySelectorAll('.selrow').forEach(c=>c.onchange=e=>{ const id=c.closest('.rowbox').dataset.id; e.target.checked?DS.sel.add(id):DS.sel.delete(id); $('#dataRemoveSel').disabled=!DS.sel.size; $('#dataRemoveSel').textContent=`remove selected (${DS.sel.size})`; });
    $('#dataRows').querySelectorAll('.delrow').forEach(b=>b.onclick=async()=>{ const id=b.closest('.rowbox').dataset.id; if(!confirm(`Remove ${id}? It is logged and restorable.`)) return; await api(`/data/${DS.file}/remove`, {ids:[id], reason:$('#dataReason').value}); toast('removed'); dataLoad(); });
    $('#dataRows').querySelectorAll('.editrow').forEach(b=>b.onclick=()=>{ const box=b.closest('.rowbox'), id=box.dataset.id, row=r.rows.find(x=>x.id===id); const txt=box.querySelector('.txt');
      if(kind==='prompt'){ txt.innerHTML=`<textarea rows="3">${esc(row.prompt)}</textarea><div class="acts"><button class="btn sm primary saverow">save</button><button class="btn sm cancelrow">cancel</button></div>`; }
      else { txt.innerHTML=`<label class="small">prompt</label><textarea rows="2">${esc(row.chosen?.[0]?.content||'')}</textarea><label class="small">chosen</label><textarea rows="3">${esc(row.chosen?.slice(1).map(m=>m.content).join('\n')||'')}</textarea><label class="small">rejected</label><textarea rows="3">${esc(row.rejected?.slice(1).map(m=>m.content).join('\n')||'')}</textarea><div class="acts"><button class="btn sm primary saverow">save</button><button class="btn sm cancelrow">cancel</button></div>`; box.querySelector('.dpo')?.remove(); }
      txt.querySelector('.cancelrow').onclick=()=>dataSearch();
      txt.querySelector('.saverow').onclick=async()=>{ const tas=[...txt.querySelectorAll('textarea')].map(t=>t.value); const body = kind==='prompt' ? {prompt:tas[0]} : {chosen:[{role:'user',content:tas[0]},{role:'assistant',content:tas[1]}], rejected:[{role:'user',content:tas[0]},{role:'assistant',content:tas[2]}]};
        try{ await api(`/data/${DS.file}/rows/${encodeURIComponent(id)}`, body, 'PUT'); toast('saved'); dataLoad(); }catch(e){ toast(e.message,true); } }; });
  }catch(e){ toast(e.message,true); } }
function highlightQ(t){ let h=esc(t||''); if(DS.q && !DS.regex){ const re=new RegExp(esc(DS.q).replace(/[.*+?^${}()|[\]\\]/g,'\\$&'),'ig'); h=h.replace(re,x=>`<mark>${x}</mark>`); } return h; }
$('#dataSearch').onclick=()=>{ DS.offset=0; dataSearch(); }; $('#dataQ').onkeydown=e=>{ if(e.key==='Enter'){ DS.offset=0; dataSearch(); } };
$('#dataSource').onchange=e=>{ DS.source=e.target.value; DS.offset=0; dataSearch(); };
$('#dataPrev').onclick=()=>{ DS.offset=Math.max(0,DS.offset-DS.limit); dataSearch(); }; $('#dataNext').onclick=()=>{ if(DS.last && DS.offset+DS.limit<DS.last.matches){ DS.offset+=DS.limit; dataSearch(); } };
$('#dataRemoveSel').onclick=async()=>{ if(!DS.sel.size) return; if(!confirm(`Remove ${DS.sel.size} rows? They are logged and restorable.`)) return; await api(`/data/${DS.file}/remove`, {ids:[...DS.sel], reason:$('#dataReason').value}); DS.sel.clear(); toast('removed'); dataLoad(); };
async function dataRemoved(){ const rows=await api(`/data/${DS.file}/removed`); $('#dataRemoved').innerHTML = rows.length ? rows.slice().reverse().map(r=>`<div class="rowbox"><span class="id">${esc(r.id)} · ${esc(r.at)} · ${esc(r.reason||'')}</span><div class="txt">${esc((r.prompt||r.chosen?.[0]?.content||'').slice(0,300))}</div><div class="acts"><button class="btn sm restore" data-id="${esc(r.id)}">restore</button></div></div>`).join('') : '<div class="small">nothing removed</div>';
  $('#dataRemoved').querySelectorAll('.restore').forEach(b=>b.onclick=async()=>{ await api(`/data/${DS.file}/restore`, {ids:[b.dataset.id]}); toast('restored'); dataLoad(); }); }

// ================================================================== SBOM panel
let sbomT=null;
$('#sbomToggle').onclick=()=>{ $('#sbomPanel').classList.add('open'); $('#dataPanel').classList.remove('open'); $('#servePanel').classList.remove('open'); sbomLoad(); };
$('#sbomClose').onclick=()=>{ $('#sbomPanel').classList.remove('open'); clearInterval(sbomT); };
$('#sbomGen').onclick=async()=>{ await api('/sbom/generate', {}); toast('SBOM generation started (PyPI advisory lookups, ~1 min)'); clearInterval(sbomT); sbomT=setInterval(sbomLoad, 3000); };
$('#sbomQ').oninput=$('#sbomVulnOnly').onchange=()=>sbomRenderPkgs();
let SB=null;
async function sbomLoad(){ const st=await api('/sbom'); $('#sbomGen').disabled=st.running; $('#sbomInfo').textContent = st.running ? `generating: ${st.progress}` : (st.error ? 'error: '+st.error : (st.latest ? `latest ${st.latest.file} · ${st.latest.n_components} components · ${st.latest.n_vulnerabilities} advisories` : 'no SBOM yet'));
  if(!st.running) clearInterval(sbomT);
  const L=st.latest; if(!L){ $('#sbomSummary').innerHTML='<div class="empty">Press Generate.</div>'; return; }
  SB=L.summary;
  $('#sbomSummary').innerHTML=`<div class="stats">${[[L.n_components,'components'],[L.n_vulnerabilities,'advisories'],...Object.entries(SB?.envs||{}).map(([e,v])=>[`${v.packages} / <span class="${v.vulnerable?'vuln':''}">${v.vulnerable}</span>`, e+' packages / vulnerable'])].map(([v,l])=>`<div class="stat"><div class="v" style="font-size:18px">${v}</div><div class="l">${l}</div></div>`).join('')}</div><div class="row"><a class="btn sm" href="/api/sbom/file/${L.file}" download>download ${L.file}</a>${(SB?.notes||[]).map(n=>`<span class="small">${esc(n)}</span>`).join(' · ')}</div>`;
  $('#sbomModules').innerHTML = SB ? `<table><tr><th>module</th><th class="num">lines</th><th>third-party imports</th><th>resolved packages</th></tr>${SB.project_modules.map(m=>`<tr><td class="mono">${esc(m.path)}</td><td class="num">${m.lines}</td><td class="mono small">${esc(m.imports.join(', '))||'–'}</td><td class="mono small">${esc((m.packages||[]).join(', '))}${m.unresolved?.length?` <span class="small">(${esc(m.unresolved.join(', '))} not in .venv)</span>`:''}</td></tr>`).join('')}</table>` : '';
  $('#sbomExtra').innerHTML = SB ? `<table><tr><th>type</th><th>name</th><th>version</th><th>purl / hash</th></tr>${SB.extra.map(c=>`<tr><td>${esc(c.type)}</td><td class="mono">${esc(c.name)}</td><td class="mono">${esc(c.version)}</td><td class="mono small">${esc(c.purl||'')}${c.hashes?` sha256 ${esc(c.hashes[0].content.slice(0,16))}…`:''}</td></tr>`).join('')}</table>` : '';
  sbomRenderPkgs(); }
function sbomRenderPkgs(){ if(!SB) return; const q=$('#sbomQ').value.toLowerCase(), only=$('#sbomVulnOnly').checked;
  const rows=SB.packages.filter(p=>(!q||p.name.toLowerCase().includes(q))&&(!only||p.vulns.length));
  $('#sbomPackages').innerHTML=`<div class="small">${rows.length} packages</div><table><tr><th>env</th><th>package</th><th>version</th><th>licence</th><th>advisories</th></tr>${rows.map(p=>`<tr><td class="small">${esc(p.env)}</td><td class="mono">${esc(p.name)}</td><td class="mono">${esc(p.version)}</td><td class="small">${esc(p.license||'')}</td><td class="small">${p.vulns.length?p.vulns.map(v=>`<div class="vuln"><b>${esc(v.id)}</b> fix: ${esc(v.fixed_in.join(', ')||'none')} — ${esc(v.summary)}</div>`).join(''):(p.error?'<span class="small">not checkable</span>':'')}</td></tr>`).join('')}</table>`; }

// ================================================================== serving panel (Kubernetes: Promote / Rollback)
let serveT=null;
api('/serving').then(()=>{ $('#serveToggle').style.display=''; }).catch(()=>{});      // 404 outside Kubernetes: no button
$('#serveToggle').onclick=()=>{ ['#dataPanel','#sbomPanel'].forEach(p=>$(p).classList.remove('open')); $('#servePanel').classList.add('open'); serveLoad(); ctlLoad(); clearInterval(serveT); serveT=setInterval(serveLoad, 5000); };
$('#serveClose').onclick=()=>{ $('#servePanel').classList.remove('open'); clearInterval(serveT); };
$('#serveRollback').onclick=async()=>{ if(!confirm('Go back to the run promoted before this one?')) return; try{ await api('/serving/rollback', {}); toast('rolled back'); }catch(e){ toast(e.message,true); } serveLoad(); };
async function serveLoad(){
  let s; try{ s=await api('/serving'); }catch(e){ $('#serveNow').innerHTML=`<div class="small vuln">${esc(e.message)}</div>`; return; }
  const d=s.deployment||{}, cur=s.current;
  const state = d.error ? `unknown (${esc(d.error)})` : `${d.ready||0} of ${d.replicas||0} running`;
  $('#serveNow').innerHTML = `<div class="row"><b>Now serving</b>${cur ? `<span class="mono">${esc(cur.run_id)}</span><span class="small">${esc(cur.model||'')} · layer ${cur.layer??'–'} · ${esc(cur.action)} ${esc(cur.at)}</span>` : '<span class="small">nothing promoted yet</span>'}</div>`
    + `<div class="small">engine <span class="mono">${esc(s.mode)}</span>${s.served_name?` · served as <span class="mono">${esc(s.served_name)}</span>`:''} · glm-serve ${state}</div>`
    + (s.busy?`<div class="small">${esc(s.busy)} …</div>`:'') + (s.error?`<div class="small vuln">${esc(s.error)}</div>`:'');
  $('#serveRollback').disabled = !!s.busy || (s.history||[]).length < 2;
  $('#serveInfo').textContent = s.mode==='vllm' ? 'vLLM: Promote points glm-serve at the run and restarts it if it is running' : 'Ollama: Promote publishes the run’s GGUF under the served name';
  const rows=s.candidates||[];
  $('#serveRuns').innerHTML = rows.length ? `<table><tr><th>run</th><th>model</th><th class="num">layer</th><th>validation</th><th></th></tr>${rows.map(r=>`<tr><td class="mono">${esc(r.run_id)}</td><td>${esc(r.model||'')}</td><td class="num">${r.layer??'–'}</td><td>${esc(r.verdict||'not validated')}</td><td>${cur&&cur.run_id===r.run_id?'<span class="small">serving</span>':`<button class="btn sm" data-promote="${esc(r.run_id)}" ${r.promotable&&!s.busy?'':'disabled'} title="${esc(r.why||'')}">Promote</button>`}</td></tr>`).join('')}</table>` : '<div class="empty">No run has an edited model yet: run Abliterate first.</div>';
  $('#serveRuns').querySelectorAll('[data-promote]').forEach(b=>b.onclick=async()=>{ const id=b.dataset.promote; if(!confirm(`Promote run ${id}? The copilot uses it from the next request.`)) return; try{ await api('/serving/promote', {run_id:id}); toast(`run ${id} promoted`); }catch(e){ toast(e.message,true); } serveLoad(); });
  const h=s.history||[];
  $('#serveHist').innerHTML = h.length ? `<table><tr><th>when</th><th>action</th><th>run</th><th>model</th><th class="num">layer</th></tr>${h.map(e=>`<tr><td class="small">${esc(e.at)}</td><td>${esc(e.action)}</td><td class="mono">${esc(e.run_id)}</td><td>${esc(e.model||'')}</td><td class="num">${e.layer??'–'}</td></tr>`).join('')}</table>` : '<div class="empty">No promotions yet.</div>';
}

// ------------------------------------------------------------------ the kill switch for glm-serve (Kubernetes only)
const CTL_BADGE = {running:'pass', starting:'warn', isolated:'warn', stopping:'fail', killed:'fail', stopped:'ghost', unknown:'ghost'};
const CTL_DOT = {running:'on', starting:'busy', stopping:'busy', isolated:'warn', killed:'bad'};
const fmtTs = ts => { const d=new Date(ts); return isNaN(d) ? (ts||'') : d.toLocaleString(); };
let ctl=null;
async function ctlLoad(){
  try{ ctl=await api('/control'); }catch(e){ return false; }        // 404 outside Kubernetes: no kill switch
  $('#modelMini').style.display='';
  $('#dotModel').className='dot '+(CTL_DOT[ctl.state]||'');
  $('#modelVal').textContent='model '+ctl.state;
  if($('#servePanel').classList.contains('open')) ctlRender();
  return true;
}
function ctlRender(){
  const c=ctl; if(!c) return;
  $('#ctlCard').style.display=''; $('#auditCard').style.display='';
  const pods=(c.pods||[]).map(p=>`${esc(p.name)} ${esc(p.phase||'')}${p.deleting?' (deleting)':''}`).join(', ')||'no pod';
  $('#ctlState').innerHTML=`<span class="badge ${CTL_BADGE[c.state]||'ghost'}">${esc(c.state)}</span> ${esc(c.deployment||'glm-serve')}: ${c.ready??0}/${c.replicas??0} ready · ${pods} · network ${c.policy?'open':'<b>cut</b>'}${c.error?` · <span class="vuln">${esc(c.error)}</span>`:''}`;
  const reps=c.replicas||0, up=reps>0||(c.pods||[]).length>0;
  $('#ctlKill').disabled = !(up || c.state==='unknown');
  $('#ctlIsolate').disabled = !(c.policy && up);
  $('#ctlRelease').disabled = !(!c.policy && reps>0);
  $('#ctlRelease').title = c.saved_copy ? '' : 'the console has no copy of the policy: re-apply the overlay';
  $('#ctlStart').disabled = reps>0;
  const a=c.audit||[];
  $('#auditList').innerHTML = a.length ? `<table><tr><th>when</th><th>action</th><th>result</th><th>who</th><th class="num">ms</th></tr>${a.map(r=>`<tr><td class="small">${esc(fmtTs(r.ts))}</td><td>${esc(r.stage)}</td><td>${r.level==='error'?'<span class="badge fail">failed</span> ':''}${esc(r.message)}${r.data&&r.data.reason?` <span class="small">“${esc(r.data.reason)}”</span>`:''}</td><td class="small">${esc((r.who&&r.who.user)||'–')} · ${esc((r.who&&(r.who.forwarded_for||r.who.ip))||'')}</td><td class="num">${r.data&&r.data.total_ms!=null?r.data.total_ms:''}</td></tr>`).join('')}</table>` : '<div class="empty">No actions yet.</div>';
}
async function ctlAct(action){
  if(action==='kill' && !confirm('Kill glm-serve now?\n\nIts network is cut, the Deployment is scaled to 0 and the pod deleted with grace period 0. A large model takes minutes to load again.')) return;
  ['#ctlKill','#ctlIsolate','#ctlRelease','#ctlStart'].forEach(b=>$(b).disabled=true);
  try{
    const r=await api('/control/'+action, {reason: $('#ctlReason').value.trim()});
    $('#ctlResult').innerHTML=`<div class="small" style="margin-top:10px"><b>${esc(r.message)}</b></div><table>${r.steps.map(s=>`<tr><td>${s.ok?'<span class="badge pass">ok</span>':'<span class="badge fail">failed</span>'}</td><td>${esc(s.step)}</td><td class="small">${esc(s.ok?s.detail:s.error)}</td><td class="num">${s.ms} ms</td></tr>`).join('')}</table>`;
    toast(r.message, !r.ok); $('#ctlReason').value='';
  }catch(e){ toast(e.message, true); $('#ctlResult').innerHTML=`<div class="small vuln" style="margin-top:10px">${esc(e.message)}</div>`; }
  await ctlLoad(); ctlRender();
}
['kill','isolate','release','start'].forEach(a=>{ $('#ctl'+a[0].toUpperCase()+a.slice(1)).onclick=()=>ctlAct(a); });
$('#modelMini').onclick=()=>$('#serveToggle').click();
ctlLoad().then(ok=>{ if(ok) setInterval(ctlLoad, 5000); });

// ------------------------------------------------------------------ copilot: models, engagement, modes, the run's flow (Kubernetes)
// Everything from n8n, the models or the form is data: it reaches the page only through esc() / escA() / textContent.
const CP = {run:null, runT:null, feedT:null, feedNext:0, feed:[], mode:'copilot', models:null, eng:null, serving:null};
const escA = s => esc(s).replace(/"/g,'&quot;').replace(/'/g,'&#39;');
const fmtTime = ts => { const d=new Date(ts); return isNaN(d) ? '' : d.toLocaleTimeString(); };
const lvl = l => l==='error' ? 'error' : (l==='warn' ? 'warn' : '');
const evRow = (e, withSource) => `<div class="cp-ev ${lvl(e.level)}"><span class="t">${esc(fmtTime(e.ts))}</span><span class="s">${esc(withSource ? e.source+' · '+e.stage : e.stage)}</span><span class="m">${esc(e.message)}</span></div>`;
const RUN_BADGE = {running:'warn', waiting:'warn', done:'pass', error:'fail', crashed:'fail', lost:'fail', canceled:'ghost'};
// per-browser conveniences only (the chosen models, the mode): the page works the same without storage
const cpStore = { get(k, d){ try{ const v=localStorage.getItem('cp.'+k); return v===null ? d : v; }catch(e){ return d; } },
                  set(k, v){ try{ localStorage.setItem('cp.'+k, v); }catch(e){} } };
const sameModel = (a, b) => String(a||'').replace(/:latest$/,'') === String(b||'').replace(/:latest$/,'');

// ---- models: operators from glm-serve, judges from the copilot's Ollama (never abliterated)
function cpFillSelect(sel, role, list, def){
  const names = list.length ? list : [def];
  const want = cpStore.get('model.'+role, '');
  const pick = names.find(n => want && n===want) || names.find(n => sameModel(n, def)) || names[0];
  sel.innerHTML = names.map(n => `<option value="${escA(n)}"${n===pick?' selected':''}>${esc(n)}${sameModel(n, def)?' (default)':''}</option>`).join('');
}
async function cpModelsLoad(fresh){
  let m; try{ m=await api('/copilot/models'+(fresh?'?fresh=true':'')); }catch(e){ $('#cpOpInfo').innerHTML=`<span class="vuln">${esc(e.message)}</span>`; return; }
  CP.models=m;
  cpFillSelect($('#cpOpModel'), 'operator', m.operator.models||[], m.operator.default);
  cpFillSelect($('#cpJudgeModel'), 'judge', m.judge.models||[], m.judge.default);
  const ex = (m.judge.excluded||[]).map(x => `${esc(x.name)} (${esc(String(x.why).split(':')[0])})`).join(', ');
  $('#cpJudgeInfo').innerHTML = (m.judge.error ? `<span class="vuln">${esc(m.judge.error)}</span>` : '') + (ex ? `not usable as judge: ${ex}` : '');
  if(m.embeddings && m.embeddings.model)
    $('#cpEmbedInfo').innerHTML = `<span class="mono">${esc(m.embeddings.model)}</span> · turns your writeups into vectors for retrieval · writes no text, so it is not a choice here`;
  try{ CP.serving=await api('/serving'); }catch(e){ CP.serving=null; }
  const sv=CP.serving, cur = sv && sv.current;
  $('#cpOpInfo').innerHTML = (m.operator.error ? `<span class="vuln">${esc(m.operator.error)}</span> · ` : '')
    + (cur ? `glm-serve serves run <span class="mono">${esc(cur.run_id)}</span>${cur.layer!=null?' (layer '+esc(cur.layer)+')':''}` : 'no run promoted yet')
    + ` · <a href="#" id="cpToServing">history and Rollback in Serving</a>`;
  // loading a run = Promote (the same audited path as the Serving panel): vLLM restarts on that run's model,
  // Ollama publishes its GGUF under the served name; the next copilot request uses it
  const cands=(sv && sv.candidates)||[];
  $('#cpLoadRun').innerHTML = cands.length ? cands.map(r=>{ const now=cur&&cur.run_id===r.run_id;
      return `<option value="${escA(r.run_id)}"${now?' selected':''}${r.promotable||now?'':' disabled'}>${esc(r.run_id)} · ${esc(r.model||'')}${r.layer!=null?' · layer '+esc(r.layer):''} · ${esc(r.verdict||'not validated')}${now?' (serving now)':(r.promotable?'':' · '+esc(r.why||'not loadable'))}</option>`; }).join('')
    : `<option value="">${sv ? 'no run has an edited model yet: run the pipeline first' : 'loading runs needs the Kubernetes deployment'}</option>`;
  $('#cpLoad').disabled = !cands.some(r=>r.promotable) || !!(sv && sv.busy);
  $('#cpLoadInfo').innerHTML = sv && sv.busy ? `<span class="badge warn">${esc(sv.busy)}</span> glm-serve is switching…` : (sv && sv.error ? `<span class="vuln">${esc(sv.error)}</span>` : '');
  clearTimeout(CP.loadT);
  if(sv && sv.busy && $('#copilotPanel').classList.contains('open')) CP.loadT=setTimeout(()=>cpModelsLoad(true), 3000);
  const toServe=$('#cpToServing'); if(toServe) toServe.onclick=(e)=>{ e.preventDefault(); $('#serveToggle').click(); };
}
$('#cpLoad').onclick=async()=>{
  const id=$('#cpLoadRun').value, cur=CP.serving && CP.serving.current; if(!id) return;
  if(cur && cur.run_id===id) return toast(`run ${id} is already the copilot`);
  if(!confirm(`Load run ${id} as the copilot? glm-serve switches to it (vLLM restarts its pod); the next copilot request uses it. Recorded in the audit log; Rollback in Serving.`)) return;
  $('#cpLoad').disabled=true;
  try{ await api('/serving/promote', {run_id:id}); toast(`loading run ${id} as the copilot`); }catch(e){ toast(e.message, true); }
  cpModelsLoad(true);
};
$('#cpOpModel').onchange=()=>cpStore.set('model.operator', $('#cpOpModel').value);
$('#cpJudgeModel').onchange=()=>cpStore.set('model.judge', $('#cpJudgeModel').value);
$('#cpModelsRefresh').onclick=()=>cpModelsLoad(true);

// ---- the engagement: one active version, saved as a new version each time, audited
const lines = v => (v||[]).join('\n');
const addLine = (t, x) => { const v=t.value.trim(); t.value=(v?v+'\n':'')+x; };
const toLocalInput = iso => { const d=new Date(iso||''); if(!iso || isNaN(d)) return ''; return new Date(d.getTime()-d.getTimezoneOffset()*60000).toISOString().slice(0,16); };
const fromLocalInput = v => { if(!v) return ''; const off=-new Date(v).getTimezoneOffset(), a=Math.abs(off);
  return (v.length===16 ? v+':00' : v) + (off>=0?'+':'-') + String(Math.floor(a/60)).padStart(2,'0') + ':' + String(a%60).padStart(2,'0'); };
function cpEngFill(r){
  r=r||{};
  $('#engName').value=r.name||''; $('#engScopeStmt').value=r.scope_statement||''; $('#engRoe').value=r.roe||'';
  $('#engIn').value=lines(r.scope_in); $('#engOut').value=lines(r.scope_out); $('#engProhibited').value=lines(r.prohibited);
  $('#engProtected').value=lines(r.protected_data);
  $('#engStart').value=toLocalInput(r.window_start); $('#engEnd').value=toLocalInput(r.window_end);
  $('#engAutoPassive').checked=!!r.autorun_passive; $('#engAutoActive').checked=!!r.autorun_active;
  $('#engActive').checked = r.active!==false; $('#engNote').value='';
}
// a data hint (app/engagement.py data_hints): suggest or broad from a sentence of the rules, broad or descriptive for a saved
// entry, unnamed (the rules protect personal data but name nothing), move (a Prohibited entry that looks like data)
function cpDataHint(h){
  const box=(badge, text, button)=>`<div class="cp-hint"><span class="badge warn">${badge}</span> ${text}${button?' '+button:''}</div>`;
  const e=`<span class="mono">${esc(h.entry)}</span>`, q=h.sentence?` (&ldquo;${esc(h.sentence)}&rdquo;)`:'';
  if(h.kind==='suggest' || (h.kind==='broad' && h.sentence))
    return box('judge only', `The rules protect ${e}, but Protected data does not list it${q}. Protected data is enforced in code; the judge alone authorized a download like this when measured.`
      + (h.kind==='broad' ? ' It is a common name: commands that name it anywhere are blocked, and wordlists or output files named like it wait for you.' : ''),
      `<button class="btn sm" data-dhint="${escA(h.entry)}">${h.kind==='broad' ? 'add anyway' : 'add to Protected data'}</button>`);
  if(h.kind==='broad') return box('broad', `${e} is a short or common name: every command that names it is blocked, and wordlists or output files named like it wait for you. Prefer a full path (/srv/hr/) or the hidden share (HR$).`);
  if(h.kind==='descriptive') return box('check', `${e} reads like a description; the gate looks for this exact text. Write the name itself (HR or HR$).`);
  if(h.kind==='unnamed') return box('judge only', `The rules protect personal data but name no file, folder, share or table${q}. Only names listed in Protected data are blocked in code: list the ones you know, and keep auto-run off while the judge is the only check.`);
  if(h.kind==='move') return box('move', `${e} is under Prohibited (tools and flags), which only matches the raw text. Protected data also reads URLs, shares, quoting and encodings.`,
    `<button class="btn sm" data-dmove="${escA(h.entry)}">move to Protected data</button>`);
  return '';                                                    // a kind this page does not know yet
}
async function cpEngLoad(){
  let s; try{ s=await api('/engagement'); }catch(e){ return; }
  CP.eng=s; const cur=s.current, c=s.ceiling||{};
  cpEngFill(cur);
  $('#cpEngVer').textContent = cur ? `v${cur.version} · ${cur.active===false?'inactive':'active'} · saved ${fmtTime(cur.saved)}${cur.by?' by '+cur.by:''}` : 'none yet: runs use LAB_ALLOWLIST alone';
  $('#cpEngCeiling').innerHTML = c.known
    ? `Ceiling (n8n enforces it, the engagement can only narrow it): LAB_ALLOWLIST <span class="mono">${esc(c.allowlist)}</span>`
    : 'The console does not know LAB_ALLOWLIST; n8n enforces it (ConfigMap copilot-scope).';
  // a host the rules put off-limits belongs in Out of scope, a name they protect in Protected data: both are code; the judge
  // alone missed such rules when measured. The buttons only fill the form: nothing applies until it is saved.
  const hints=s.hints||[];
  $('#engHints').innerHTML = hints.map(h=>`<div class="cp-hint"><span class="badge warn">judge only</span> The rules put <span class="mono">${esc(h.host)}</span> off-limits, but Out of scope does not list it (&ldquo;${esc(h.sentence)}&rdquo;). Out of scope is enforced in code; the judge alone missed rules like this when measured. <button class="btn sm" data-hint="${escA(h.host)}">add to Out of scope</button></div>`).join('')
    + (s.data_hints||[]).map(cpDataHint).join('');
  $('#engHints').querySelectorAll('[data-hint]').forEach(b=>b.onclick=()=>{ addLine($('#engOut'), b.dataset.hint); b.disabled=true; b.textContent='added: save to apply'; });
  $('#engHints').querySelectorAll('[data-dhint]').forEach(b=>b.onclick=()=>{ addLine($('#engProtected'), b.dataset.dhint); b.disabled=true; b.textContent='added: save to apply'; });
  // a move also takes the entry out of Prohibited, which the console splits on lines and commas and dedups ignoring case
  $('#engHints').querySelectorAll('[data-dmove]').forEach(b=>b.onclick=()=>{ const x=b.dataset.dmove, t=$('#engProhibited');
    addLine($('#engProtected'), x);
    t.value=t.value.split(/[\n,]/).map(v=>v.trim()).filter(v=>v && v.replace(/\s+/g,' ').toLowerCase()!==x.toLowerCase()).join('\n');
    b.disabled=true; b.textContent='moved: save to apply'; });
  const cap=[]; if(c.autorun_passive===false) cap.push('passive'); if(c.autorun_active===false) cap.push('active');
  $('#engAutoCap').textContent = cap.length ? `capped: the ${cap.join(' and ')} tier is off in LAB_AUTORUN_* (copilot.env)` : '';
  const off=-new Date().getTimezoneOffset(), a=Math.abs(off);
  $('#engTz').textContent = `your browser's time, UTC${off>=0?'+':'-'}${String(Math.floor(a/60)).padStart(2,'0')}:${String(a%60).padStart(2,'0')}`;
  const vs=s.versions||[];
  $('#engVersionList').innerHTML = vs.length ? `<table><tr><th>version</th><th>saved</th><th>by</th><th>name</th><th>note</th><th></th></tr>${vs.map(v=>`<tr><td class="mono">v${esc(v.version)}${v.active===false?' (inactive)':''}</td><td>${esc(fmtTime(v.saved))}</td><td>${esc(v.by||'')}</td><td>${esc(v.name||'')}</td><td>${esc(v.note||'')}</td><td><button class="btn sm" data-engv="${escA(v.version)}">load into the form</button></td></tr>`).join('')}</table>` : 'none yet';
  $('#engVersionList').querySelectorAll('[data-engv]').forEach(b=>b.onclick=async()=>{
    try{ cpEngFill(await api('/engagement/versions/'+encodeURIComponent(b.dataset.engv))); toast(`v${b.dataset.engv} loaded: save it to make it the active version again`); }catch(e){ toast(e.message, true); } });
}
$('#engSave').onclick=async()=>{
  const body={name:$('#engName').value, scope_statement:$('#engScopeStmt').value, roe:$('#engRoe').value, scope_in:$('#engIn').value,
    scope_out:$('#engOut').value, prohibited:$('#engProhibited').value, protected_data:$('#engProtected').value, window_start:fromLocalInput($('#engStart').value),
    window_end:fromLocalInput($('#engEnd').value), autorun_passive:$('#engAutoPassive').checked, autorun_active:$('#engAutoActive').checked,
    active:$('#engActive').checked, note:$('#engNote').value};
  $('#engSave').disabled=true;
  try{ const r=await api('/engagement', body); toast(`engagement v${r.version} saved`); await cpEngLoad(); }catch(e){ toast(e.message, true); }
  $('#engSave').disabled=false;
};

// ---- modes: copilot (the abliterated model proposes), manual (a typed command), direct prompt (no copilot)
function cpSetMode(m){
  CP.mode=m; cpStore.set('mode', m);
  document.querySelectorAll('.cp-modes [data-mode]').forEach(b=>{ const on=b.dataset.mode===m; b.classList.toggle('active', on); b.setAttribute('aria-selected', on?'true':'false'); });
  document.querySelectorAll('.cp-mode').forEach(d=>{ d.hidden = !d.dataset.for.split(' ').includes(m); });
}
document.querySelectorAll('.cp-modes [data-mode]').forEach(b=>b.onclick=()=>cpSetMode(b.dataset.mode));
async function cpStart(body){
  try{
    const r=await api('/copilot/run', {...body, operator_model:$('#cpOpModel').value||'', judge_model:$('#cpJudgeModel').value||''});
    toast(`copilot run ${r.id} started`); cpShowRun(r.id);
  }catch(e){ toast(e.message, true); }
}
$('#cpRun').onclick=async()=>{
  const task=$('#cpTask').value.trim(), target=$('#cpTarget').value.trim();
  if(!task || !target) return toast('task and target are both needed', true);
  $('#cpRun').disabled=true; await cpStart({task, target, mode:'copilot'}); $('#cpRun').disabled=false;
};
$('#cpCheck').onclick=async()=>{
  const command=$('#cpCommand').value.trim(), target=$('#cpTarget').value.trim();
  if(!command || !target) return toast('target and command are both needed', true);
  $('#cpCheck').disabled=true; await cpStart({target, command, task:$('#cpWhy').value.trim(), mode:'manual'}); $('#cpCheck').disabled=false;
};
// the same extraction as the workflow's Parse proposal: a JSON object, else a fenced block, else the first line
function cpExtractCommand(raw){
  const m=String(raw||'').match(/\{[\s\S]*\}/);
  if(m){ try{ const p=JSON.parse(m[0]); if(p && p.command) return {command:String(p.command), target:p.target?String(p.target):''}; }catch(e){} }
  const fenced=(String(raw||'').match(/```(?:bash|sh)?\n([\s\S]*?)```/)||[])[1];
  return {command:(fenced||String(raw||'')).split('\n').map(s=>s.trim()).find(Boolean)||'', target:''};
}
function cpToManual(command, target){
  const all=String(command||'').split(/\r?\n/).map(s=>s.trim()).filter(Boolean);
  cpSetMode('manual'); $('#cpCommand').value=all[0]||'';
  if(target && !$('#cpTarget').value.trim()) $('#cpTarget').value=target;
  $('#cpCommand').focus();
  toast(all.length>1 ? 'only the first line was taken: one command per check' : 'taken over: check it, then "Check and stage"');
}
$('#cpUseCmd').onclick=()=>{ const x=cpExtractCommand($('#cpAnswer').textContent); if(!x.command) return toast('no command in the answer', true); cpToManual(x.command, x.target); };
$('#cpSend').onclick=async()=>{
  const prompt=$('#cpPrompt').value.trim(); if(!prompt) return;
  const out=$('#cpAnswer'), info=$('#cpPromptInfo'); out.textContent=''; info.textContent='streaming…'; $('#cpSend').disabled=true; $('#cpUseCmd').disabled=true;
  try{
    const r=await fetch('/api/model/chat', {method:'POST', headers:{'Content-Type':'application/json'},
      body:JSON.stringify({prompt, max_tokens:+$('#cpMax').value || 512, model:$('#cpOpModel').value||''})});
    if(!r.ok){ let m=r.statusText; try{ m=(await r.json()).detail || m; }catch(e){} throw new Error(m); }
    const rd=r.body.getReader(), dec=new TextDecoder(); let buf='';
    for(;;){
      const {value, done}=await rd.read(); if(done) break;
      buf+=dec.decode(value, {stream:true}); let i;
      while((i=buf.indexOf('\n'))>=0){
        const line=buf.slice(0, i); buf=buf.slice(i+1); if(!line.trim()) continue;
        const ev=JSON.parse(line);
        if(ev.token) out.textContent+=ev.token;
        else if(ev.done) info.textContent=`${ev.tokens} pieces in ${ev.ms} ms from ${$('#cpOpModel').value||'the served model'}`;
        else if(ev.error){ info.textContent=''; toast(ev.error, true); }
      }
    }
  }catch(e){ info.textContent=''; toast(e.message, true); }
  $('#cpSend').disabled=false; $('#cpUseCmd').disabled=!out.textContent.trim();
};

// ---- the run as a flow: the copilot's lane (gates, judge) and the abliterated model's lane, the prompt crossing over
// and the answer coming back, then "about to be executed"
const STATE_ICON = {ok:'✓', blocked:'✕', active:'…', pending:'·', skipped:'–', error:'!', warn:'!'};
function cpBox(state, title, body, extra){
  return `<div class="cp-box ${state}"><div class="cp-box-h"><span class="cp-ic" aria-hidden="true">${STATE_ICON[state]||'·'}</span><b>${title}</b></div>${body?`<div class="cp-box-b">${body}</div>`:''}${extra||''}</div>`;
}
const cpPre = (label, text) => text ? `<details class="cp-pre"><summary>${esc(label)}</summary><pre>${esc(text)}</pre></details>` : '';
function cpFlowHtml(r){
  const evs=r.events||[], first=s=>evs.find(e=>e.stage===s);
  const live=r.status==='running', manual=r.mode==='manual';
  const fatal=evs.find(e=>e.stage==='error' && e.level==='error');
  const scope=first('scope'), retr=first('retrieval'), prompt=first('prompt'), prop=first('proposal'), pol=first('policy'), jp=first('judge_prompt'), judge=first('judge');
  // each step from the one before: its own event decides; without one it is in progress (the run lives), failed (the
  // run failed there) or never reached; after a step in progress, pending; after a block, skipped
  const next = (prev, ev, fromEv) => {
    if(ev) return fromEv(ev);
    if(prev==='ok' || prev==='warn') return live ? 'active' : (fatal ? 'error' : 'skipped');
    return (prev==='active' || prev==='pending') ? 'pending' : 'skipped';
  };
  const opModel=(prompt&&prompt.data.model)||r.operator_model||'glm-abl', judgeModel=(jp&&jp.data.model)||r.judge_model||'judge';
  const eng=r.engagement, rows=[];
  // on a phone the lanes stack: each box of the model's lane says so itself (data-lane)
  const lane = escA('ABLITERATED MODEL · '+opModel);
  const row = (cop, mid, abl, cls) => rows.push(`<div class="cp-row ${cls||''}"><div class="cp-cell cop">${cop||''}</div><div class="cp-cell mid">${mid||''}</div><div class="cp-cell abl" data-lane="${lane}">${abl||''}</div></div>`);
  const fail = st => (st==='error' && fatal) ? esc(fatal.message) : '';
  row(`<div class="cp-lane-h">Copilot<small>n8n gates · judge ${esc(judgeModel)}</small></div>`, '', `<div class="cp-lane-h">Abliterated model<small>${esc(opModel)} on glm-serve</small></div>`, 'head');
  row(cpBox('ok', manual ? 'Manual command' : 'Task', `<span class="mono">${esc(manual ? (r.command||'') : r.task)}</span><div class="small">target <span class="mono">${esc(r.target)}</span> · ${eng ? `engagement v${esc(eng.version)}${eng.name?' '+esc(eng.name):''}` : 'no engagement: LAB_ALLOWLIST alone'}</div>`));
  const S = next('ok', scope, e => e.data.scopeOk ? 'ok' : 'blocked');
  row(cpBox(S, 'Scope gate', scope ? esc(scope.message) : (S==='active' ? 'checking…' : fail(S))));
  let P;                                                   // the proposal step: the model's answer, or the typed command
  if(manual){
    row(cpBox('skipped', 'Retrieval', 'manual command: no references'), '', cpBox('skipped', 'Not asked', 'a typed command goes straight to the gates'));
    P = next(S, prop, () => 'ok');
    row(cpBox(P, 'Typed by the operator', prop ? `<code class="cp-cmd">${esc(prop.data.proposal.command)}</code>` : fail(P)));
  } else {
    const R = next(S, retr, e => e.level==='warn' ? 'warn' : 'ok');
    row(cpBox(R, 'Retrieval', retr ? esc(retr.message) : (R==='active' ? 'searching the writeups…' : fail(R))));
    const B = next(R, prompt, () => 'ok');
    P = next(B, prop, () => 'ok');
    const recv = B!=='ok' ? (B==='skipped' ? 'skipped' : 'pending') : P;            // the model's side of the same step
    row(cpBox(B, 'Prompt built', prompt ? `${esc(prompt.data.prompt.length)} characters${prompt.data.refCount?' · '+esc(prompt.data.refCount)+' references':''}${cpPre('show the prompt', prompt.data.prompt)}` : fail(B)),
        `<div class="cp-arrow right ${B}"><span>prompt</span></div>`,
        cpBox(recv, `${esc(opModel)} receives it`, recv==='active' ? 'thinking…' : (recv==='ok' ? 'answered' : fail(recv))), 'cross');
    const ans = P==='active' ? 'pending' : P;
    row(cpBox(ans, 'Proposal', prop ? `<code class="cp-cmd">${esc(prop.data.proposal.command || '(no command)')}</code>${prop.data.proposal.rationale?`<div class="small">${esc(prop.data.proposal.rationale)}</div>`:''}` : ''),
        `<div class="cp-arrow left ${ans}"><span>answer</span></div>`,
        cpBox(ans, 'Answer', prop ? (cpPre('show the raw answer', prop.data.raw) || '<span class="small">(empty)</span>') : ''), 'cross');
  }
  const G = next(P, pol, e => e.data.allowed ? 'ok' : 'blocked');
  // passed: why it does or doesn't auto-run; blocked: every reason, once
  row(cpBox(G, 'Policy gate', pol ? (pol.data.allowed || !(pol.data.reasons||[]).length ? esc(pol.message)
    : `blocked<ul class="small cp-reasons">${pol.data.reasons.map(x=>`<li>${esc(x)}</li>`).join('')}</ul>`) : (G==='active' ? 'checking…' : fail(G))));
  const J = next(G, judge, e => e.data.allowed ? 'ok' : 'blocked');
  row(cpBox(J, `Judge · ${esc(judgeModel)}`, (jp ? cpPre(`show the judge's prompt (${jp.data.prompt.length} characters)`, jp.data.prompt) : '')
    + (judge ? `<div>${esc(judge.data.verdict || judge.message)}</div>` : (J==='active' ? 'deciding…' : fail(J)))));
  return rows.join('');
}
function cpStagedHtml(r){
  const res=r.result, evs=r.events||[], judge=evs.find(e=>e.stage==='judge');
  const fatal=evs.find(e=>e.stage==='error' && e.level==='error');
  const staged=(res && res.staged) || (judge && judge.data.staged) || '';
  const execBtn = `<button class="btn sm" disabled title="Execute is disabled by design: the workflow's Execute node is off and no lab runner is configured (LAB_RUNNER_URL). Run it yourself if you decide to.">Execute (disabled)</button>`;
  if(staged){
    const how = res ? (res.autoRun ? `auto-run tier ${esc(res.tier||'')}` : 'waiting for approval in n8n') : 'authorized';
    return `<div class="cp-staged ok"><div class="cp-staged-h"><b>About to be executed</b><span class="badge pass">${how}</span></div>`
      + `<code class="cp-staged-cmd">${esc(staged)}</code>`
      + `<div class="row"><button class="btn sm" id="cpCopy">Copy</button><button class="btn sm" id="cpEdit">Edit as manual command</button>${execBtn}</div>`
      + `<div class="small">target <span class="mono">${esc(r.target)}</span>${judge?` · judge: ${esc((judge.data.verdict||'').split('\n')[0])}`:''}${res&&res.engagement?` · engagement v${esc(res.engagement.version)}`:''}${res?` · ${esc(res.next)}`:''}</div></div>`;
  }
  if(res && !res.allowed){
    return `<div class="cp-staged blocked"><div class="cp-staged-h"><b>About to be executed</b><span class="badge fail">nothing</span></div>`
      + `<div><b>${esc(res.title)}</b></div>${(res.reasons||[]).length?`<ul class="small cp-reasons">${res.reasons.map(x=>`<li>${esc(x)}</li>`).join('')}</ul>`:''}<div class="small">${esc(res.next)}</div></div>`;
  }
  if(['running','waiting'].includes(r.status)) return `<div class="cp-staged pending"><div class="cp-staged-h"><b>About to be executed</b><span class="badge warn">the gates are still deciding</span></div><code class="cp-staged-cmd muted">…</code></div>`;
  return `<div class="cp-staged blocked"><div class="cp-staged-h"><b>About to be executed</b><span class="badge ghost">nothing</span></div><div class="small">${fatal ? 'The run failed: '+esc(fatal.message) : 'The run ended ('+esc(r.status)+') before anything was staged.'}</div></div>`;
}
function cpRenderRun(){
  const r=CP.run; if(!r) return;
  $('#cpRunCard').style.display='';
  $('#cpRunTitle').innerHTML = `Run ${esc(r.id)} <span class="badge ${RUN_BADGE[r.status]||'ghost'}">${esc(r.status)}</span> <span class="small">${esc(r.mode||'copilot')}</span>`;
  $('#cpStop').disabled = !['running','waiting'].includes(r.status);
  $('#cpFlow').innerHTML = cpFlowHtml(r);
  $('#cpStaged').innerHTML = cpStagedHtml(r);
  $('#cpEvents').innerHTML = (r.events||[]).map(e=>evRow(e, false)).join('');
  const staged = (r.result && r.result.staged) || ((r.events||[]).find(e=>e.stage==='judge')||{data:{}}).data.staged;
  const copy=$('#cpCopy'); if(copy) copy.onclick=async()=>{ try{ await navigator.clipboard.writeText(staged); toast('copied'); }catch(e){ toast('copy failed: select the command and copy it', true); } };
  const edit=$('#cpEdit'); if(edit) edit.onclick=()=>cpToManual(staged, r.target);
}
async function cpShowRun(id){
  clearTimeout(CP.runT);
  try{ CP.run=await api('/copilot/runs/'+encodeURIComponent(id)); }catch(e){ toast(e.message, true); return; }
  cpRenderRun();
  if(['running','waiting'].includes(CP.run.status) && $('#copilotPanel').classList.contains('open'))
    CP.runT=setTimeout(()=>cpShowRun(id), CP.run.status==='waiting' ? 5000 : 1000);
  else cpLoad();
}
async function cpLoad(){
  let s; try{ s=await api('/copilot'); }catch(e){ return false; }        // 404 outside Kubernetes: no copilot button
  $('#copilotToggle').style.display='';
  $('#cpConn').innerHTML = s.configured
    ? `<span class="badge pass">connected</span> n8n at <span class="mono">${esc(s.n8n)}</span>`
    : `<span class="badge warn">not connected</span> missing: <span class="mono">${esc((s.missing||[]).join(', '))}</span>. Run <span class="mono">deploy/n8n/connect_console.py</span> once (deploy/k8s/README.md, section Copilot).`;
  $('#cpRun').disabled = $('#cpCheck').disabled = !s.configured;
  $('#cpSend').disabled = !(s.model && s.model.configured);
  const runs=s.runs||[];
  $('#cpRuns').innerHTML = runs.length ? `<table><tr><th>run</th><th>mode</th><th>task / command</th><th>target</th><th>status</th><th>result</th></tr>${runs.map(r=>`<tr data-run="${escA(r.id)}" class="cp-runrow"><td class="mono">${esc(r.id)}</td><td>${esc(r.mode||'copilot')}</td><td>${r.mode==='manual'?`<span class="mono">${esc(r.command||'')}</span>`:esc(r.task)}</td><td class="mono">${esc(r.target)}</td><td><span class="badge ${RUN_BADGE[r.status]||'ghost'}">${esc(r.status)}</span></td><td>${esc(r.title||'')}</td></tr>`).join('')}</table>` : '<div class="empty">No runs from this console yet.</div>';
  $('#cpRuns').querySelectorAll('[data-run]').forEach(tr=>tr.onclick=()=>cpShowRun(tr.dataset.run));
  return true;
}
async function cpFeedLoad(){
  let f; try{ f=await api('/feed?after='+CP.feedNext+'&limit=300'); }catch(e){ return; }
  if(!f.events.length) return;
  CP.feed=CP.feed.concat(f.events).slice(-500); CP.feedNext=f.next; cpFeedRender();
  if(f.events.some(e=>e.source==='copilot')) cpLoad();
}
function cpFeedRender(){
  const src=$('#cpFeedSrc').value, ev=CP.feed.filter(e=>!src || e.source===src).slice(-200).reverse();
  $('#cpFeed').innerHTML = ev.length ? ev.map(e=>evRow(e, true)).join('') : '<div class="empty">Nothing yet.</div>';
}
$('#cpFeedSrc').onchange=cpFeedRender;
$('#cpStop').onclick=async()=>{
  const r=CP.run; if(!r || !confirm(`Stop copilot run ${r.id} in n8n?`)) return;
  try{ await api('/copilot/runs/'+encodeURIComponent(r.id)+'/stop', {}); toast('stopped'); }catch(e){ toast(e.message, true); }
  cpShowRun(r.id);
};
$('#copilotToggle').onclick=()=>{
  ['#dataPanel','#sbomPanel','#servePanel'].forEach(p=>$(p).classList.remove('open'));
  $('#copilotPanel').classList.add('open'); cpLoad(); cpFeedLoad(); cpModelsLoad(false); cpEngLoad();
  clearInterval(CP.feedT); CP.feedT=setInterval(cpFeedLoad, 1500);
  if(CP.run) cpShowRun(CP.run.id);
};
const cpClose=()=>{ $('#copilotPanel').classList.remove('open'); clearInterval(CP.feedT); clearTimeout(CP.runT); clearTimeout(CP.loadT); };
$('#copilotClose').onclick=cpClose;
['#dataToggle','#sbomToggle','#serveToggle'].forEach(b=>$(b).addEventListener('click', cpClose));
cpSetMode(['copilot','manual','direct'].includes(cpStore.get('mode','copilot')) ? cpStore.get('mode','copilot') : 'copilot');
cpLoad();

// ------------------------------------------------------------------ knowledge uploads (the copilot's retrieval)
const KN = {info:null, previewed:null, t:null};
const fileKey = f => f ? `${f.name}|${f.size}|${f.lastModified}` : '';
const fmtBytes = n => n==null ? '' : (n >= 1048576 ? (n/1048576).toFixed(1)+' MB' : (n >= 1024 ? Math.round(n/1024)+' KB' : n+' B'));
const KN_BADGE = {indexed:'pass', queued:'warn', ingesting:'warn', error:'fail', 'not indexed':'ghost'};
function knGate(){
  const f=$('#knFile').files[0], src=$('#knSource').value;
  const needPreview = src==='engagement' && KN.previewed!==fileKey(f)+'|'+src;
  $('#knUpload').disabled = !f || needPreview || !(KN.info && KN.info.configured);
  $('#knPreview').disabled = !f;
  $('#knSourceInfo').textContent = ((KN.info && KN.info.sources) || {})[src] || '';
  $('#knInfo').textContent = needPreview && f ? 'engagement notes: preview the redactions first' : '';
}
async function knLoad(){
  let k; try{ k=await api('/knowledge'); }catch(e){ return false; }
  KN.info=k;
  if(!k.configured){ $('#knowledgeToggle').style.display='none'; return false; }       // no vector store here
  $('#knowledgeToggle').style.display='';
  const sel=$('#knSource');
  if(!sel.options.length) sel.innerHTML=Object.keys(k.sources).map(s=>`<option value="${escA(s)}">${esc(s)}</option>`).join('');
  $('#knStore').innerHTML = k.qdrant_error ? `<span class="vuln">vector store: ${esc(k.qdrant_error)}</span>` : `collection <span class="mono">${esc(k.collection)}</span>`;
  const docs=k.docs||[];
  $('#knDocs').innerHTML = docs.length ? `<div style="overflow-x:auto"><table><tr><th>document</th><th>title</th><th class="num">chunks</th><th class="num">size</th><th>status</th><th></th></tr>${docs.map(d=>{
      const st = d.status==='ingesting' && d.progress && d.progress[1] ? `ingesting ${d.progress[0]}/${d.progress[1]}` : d.status;
      return `<tr><td class="mono">${esc(d.doc)}${d.file?'':' <span class="small">(vectors only)</span>'}</td><td>${esc(d.title)}</td><td class="num">${d.chunks}</td><td class="num">${esc(fmtBytes(d.size))}</td><td><span class="badge ${KN_BADGE[d.status]||'ghost'}" title="${escA(d.error||'')}">${esc(st)}</span>${d.error?` <span class="small vuln">${esc(d.error)}</span>`:''}</td><td><button class="btn sm danger" data-kndel="${escA(d.doc)}" ${['queued','ingesting'].includes(d.status)?'disabled':''}>Delete</button></td></tr>`; }).join('')}</table></div>`
    : '<div class="empty">No documents yet. Retrieval runs without references until there are some.</div>';
  $('#knDocs').querySelectorAll('[data-kndel]').forEach(b=>b.onclick=async()=>{
    const doc=b.dataset.kndel; if(!confirm(`Delete ${doc}? Its file and its chunks in the vector store are removed.`)) return;
    try{ await api('/knowledge/delete', {doc}); toast(`${doc} deleted`); }catch(e){ toast(e.message, true); }
    knLoad(); });
  knGate();
  clearTimeout(KN.t);
  if(docs.some(d=>['queued','ingesting'].includes(d.status)) && $('#knowledgePanel').classList.contains('open')) KN.t=setTimeout(knLoad, 1500);
  return true;
}
async function knSend(kind){
  const f=$('#knFile').files[0], src=$('#knSource').value; if(!f) return;
  if(KN.info && f.size > KN.info.max_bytes) return toast(`${f.name} is larger than ${fmtBytes(KN.info.max_bytes)}`, true);
  const r=await fetch(`/api/knowledge/${kind}?source=${encodeURIComponent(src)}&name=${encodeURIComponent(f.name)}`, {method:'POST', headers:{'Content-Type':'application/octet-stream'}, body:f});
  let body; try{ body=await r.json(); }catch(e){ body={}; }
  if(!r.ok) throw new Error(body.detail || r.statusText);
  return body;
}
$('#knPreview').onclick=async()=>{
  const out=$('#knPreviewOut'); out.innerHTML='<div class="small">reading…</div>';
  try{
    const p=await knSend('preview'), red=Object.entries(p.redactions||{});
    out.innerHTML = `<div class="small" style="margin-top:8px"><b>${esc(p.doc)}</b>: ${p.chars.toLocaleString()} characters, ${p.chunks} chunk${p.chunks===1?'':'s'}</div>`
      + (red.length ? `<table style="max-width:420px"><tr><th>redacted</th><th class="num">count</th></tr>${red.map(([k,v])=>`<tr><td class="mono">${esc(k)}</td><td class="num">${v}</td></tr>`).join('')}</table>` : '<div class="small">no redactions</div>')
      + `<pre class="cp-answer" id="knPreviewText"></pre>` + (p.truncated ? '<div class="small">(first 30,000 characters)</div>' : '');
    $('#knPreviewText').textContent = p.scrubbed!=null ? p.scrubbed : p.sample;
    KN.previewed=fileKey($('#knFile').files[0])+'|'+p.source;
  }catch(e){ out.innerHTML=''; toast(e.message, true); }
  knGate();
};
$('#knUpload').onclick=async()=>{
  $('#knUpload').disabled=true;
  const sent=$('#knFile').files[0];   // a file picked while this one uploads stays picked
  try{ const u=await knSend('upload'); toast(`${u.doc} uploaded: ingesting`); if($('#knFile').files[0]===sent){ $('#knFile').value=''; $('#knPreviewOut').innerHTML=''; KN.previewed=null; } }catch(e){ toast(e.message, true); }
  knLoad();
};
$('#knFile').onchange=knGate; $('#knSource').onchange=knGate;
$('#knowledgeToggle').onclick=()=>{
  ['#dataPanel','#sbomPanel','#servePanel','#copilotPanel'].forEach(p=>$(p).classList.remove('open'));
  cpClose(); clearInterval(serveT);                    // their pollers stop with their panels
  $('#knowledgePanel').classList.add('open'); knLoad();
};
const knClose=()=>{ $('#knowledgePanel').classList.remove('open'); clearTimeout(KN.t); };
$('#knowledgeClose').onclick=knClose;
['#dataToggle','#sbomToggle','#serveToggle','#copilotToggle'].forEach(b=>$(b).addEventListener('click', knClose));
knLoad();
