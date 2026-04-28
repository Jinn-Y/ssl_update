/* 全局状态 */
const S={mode:'all',search:'',page:1,pageSize:20,pagination:{total:0,pages:0},editingId:null,syncStates:{},currentServers:[]};

/* 工具函数 */
function esc(v){return String(v??'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;')}
function now(){return new Date().toLocaleTimeString('zh-CN',{hour:'2-digit',minute:'2-digit',second:'2-digit'})}
function $(id){return document.getElementById(id)}
function b64UrlToBuf(v){const p='='.repeat((4-v.length%4)%4);const n=(v+p).replace(/-/g,'+').replace(/_/g,'/');const b=atob(n);const u=new Uint8Array(b.length);for(let i=0;i<b.length;i++)u[i]=b.charCodeAt(i);return u.buffer}
function bufToB64Url(buf){const u=new Uint8Array(buf);let b='';for(const x of u)b+=String.fromCharCode(x);return btoa(b).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/g,'')}
function fmtDays(d){return d<0?`已过期 ${Math.abs(d)} 天`:d===0?'今天到期':`剩余 ${d} 天`}
function getSelectedDomain(){return ($('serverDomain')?.value)||($('domain')?.value)||''}

/* 视图切换 */
function switchView(name){
    document.querySelectorAll('.view').forEach(v=>v.classList.remove('active'));
    document.querySelectorAll('.nav-item,.tab-item').forEach(n=>n.classList.remove('active'));
    const view=$('view-'+name);if(view)view.classList.add('active');
    document.querySelectorAll(`[data-view="${name}"]`).forEach(n=>n.classList.add('active'));
    if(name==='dashboard')loadDashboard();
    if(name==='servers'){loadServerDomains();loadServers()}
    if(name==='sync')loadDomains();
    if(name==='account'){loadTwoFactorStatus();loadPasskeys()}
}

/* 主题 */
function applyTheme(t){
    const r=document.documentElement;
    r.style.colorScheme=t==='system'?'light dark':t;
    if(t==='system')delete r.dataset.theme;else r.dataset.theme=t;
}
function initTheme(){
    const t=localStorage.getItem('theme-preference')||'system';
    const sel=$('themeSelect');if(sel)sel.value=t;
    applyTheme(t);
}

/* 消息提示 */
function showMsg(el,text,type='success'){el.textContent=text;el.className=`message visible ${type}`}
function clearMsg(el){el.textContent='';el.className='message'}

/* ===== 日志面板 ===== */
function logStart(title,meta){
    const p=$('logPanel');p.classList.add('active');
    $('logTitleBar').textContent=title;
    $('logBody').innerHTML='';
    logSetStatus('running','运行中');
    logSetSummary('');
    /* 自动滚动到日志面板 */
    setTimeout(()=>p.scrollIntoView({behavior:'smooth',block:'start'}),100);
}
function logSetStatus(cls,text){
    const b=$('logStatusBadge');b.className='log-status-badge';
    if(cls)b.classList.add(cls);b.textContent=text;
}
function logSetSummary(t){
    const s=$('logSummary');
    if(!t){s.textContent='';s.className='log-summary';return}
    s.textContent=t;s.className='log-summary visible';
}
function logAdd(msg,type='info',label=''){
    const body=$('logBody');
    const tags={info:'INFO',warn:'WARN',error:'ERROR',ok:'OK',task:'TASK'};
    const e=document.createElement('div');e.className='log-entry';
    e.innerHTML=`<span class="log-ts">${now()}</span><span class="log-tag ${type}">${label||tags[type]||'INFO'}</span><span class="log-msg">${esc(msg)}</span>`;
    body.appendChild(e);body.scrollTop=body.scrollHeight;
}
function logFinish(status,summary){
    logSetStatus(status,status==='success'?'完成':'失败');
    logSetSummary(summary);
}
function inferType(m){return m.includes('[ERROR]')?'error':m.includes('[WARN]')?'warn':'info'}

/* SSE 流消费 */
async function consumeStream(resp,opts){
    const{onOk,onFail,metaFn,okText,failPre}=opts;
    if(!resp.ok){const t=await resp.text();logAdd(t,'error');logFinish('error',t);if(onFail)onFail(t);return}
    const reader=resp.body.getReader();const dec=new TextDecoder();
    while(true){
        const{done,value}=await reader.read();if(done)break;
        const chunk=dec.decode(value);
        chunk.split('\n').forEach(line=>{
            if(!line.startsWith('data: '))return;
            const msg=line.slice(6);
            if(msg==='[KEEPALIVE]'||msg==='[DONE]')return;
            if(msg.startsWith('[SUCCESS]')){logAdd(okText,'ok','OK');logFinish('success',okText);if(onOk)onOk();return}
            if(msg.startsWith('[FAILED]')){const f=msg.replace('[FAILED]','').trim()||'存在失败节点';const t=failPre+f;logAdd(t,'error','FAIL');logFinish('error',t);if(onFail)onFail(f);return}
            logAdd(msg,inferType(msg));
        });
    }
}

/* ===== 仪表盘 ===== */
async function loadDashboard(){
    try{
        const[srvRes,domRes]=await Promise.all([fetch('/api/servers?page=1&page_size=1'),fetch('/api/domains')]);
        const srvData=await srvRes.json();const domData=await domRes.json();
        const total=srvData.success?srvData.pagination.total:0;
        $('statServers').textContent=total;
        $('statDomains').textContent=domData.success?domData.domains.length:0;
        // 加载证书状态
        if(domData.success&&domData.domains.length){
            const results=await Promise.all(domData.domains.map(async d=>{
                try{const r=await fetch(`/api/cert_info/${encodeURIComponent(d)}`);return{domain:d,data:await r.json()}}
                catch(e){return{domain:d,data:null}}
            }));
            let enabled=0;
            const list=$('certList');list.innerHTML='';
            results.forEach(({domain,data})=>{
                if(data&&data.success){
                    enabled++;
                    const cls=data.days_left<7?'danger':data.days_left<30?'warn':'ok';
                    list.innerHTML+=`<div class="cert-item"><span class="cert-domain">${esc(domain)}</span><span class="cert-expiry ${cls}">${fmtDays(data.days_left)}</span></div>`;
                }else{
                    list.innerHTML+=`<div class="cert-item"><span class="cert-domain">${esc(domain)}</span><span class="cert-expiry danger">读取失败</span></div>`;
                }
            });
            $('statCerts').textContent=enabled;
        }
    }catch(e){console.error('Dashboard load error',e)}
}

/* ===== 域名加载（通用，两阶段） ===== */
async function fillDomainSelect(sel){
    sel.innerHTML='<option value="">加载中...</option>';
    try{
        const r=await fetch('/api/domains');const d=await r.json();
        if(!d.success)throw new Error(d.error);
        if(!d.domains.length){sel.innerHTML='<option value="">未找到可用证书</option>';return}
        /* 第一阶段：立即填充域名列表，让用户可以选择 */
        sel.innerHTML='<option value="">请选择证书域名</option>';
        d.domains.forEach(dm=>{
            const o=document.createElement('option');o.value=dm;o.textContent=dm;
            sel.appendChild(o);
        });
        /* 第二阶段：后台异步获取证书到期信息，更新 option 文本 */
        d.domains.forEach(async(dm)=>{
            try{
                const cr=await fetch(`/api/cert_info/${encodeURIComponent(dm)}`);
                const info=await cr.json();
                if(info&&info.success){
                    const opt=sel.querySelector(`option[value="${CSS.escape(dm)}"]`);
                    if(opt)opt.textContent=`${dm} (剩余 ${info.days_left} 天)`;
                }
            }catch(e){/* 证书信息加载失败不影响选择 */}
        });
    }catch(e){sel.innerHTML='<option value="">加载失败</option>'}
}
async function loadDomains(){await fillDomainSelect($('domain'))}
async function loadServerDomains(){await fillDomainSelect($('serverDomain'))}

/* ===== 服务器管理 ===== */
async function loadServers(){
    const tbody=$('serverTableBody');tbody.innerHTML='<tr><td colspan="7" class="empty-state">正在加载...</td></tr>';
    try{
        const p=new URLSearchParams({page:S.page,page_size:S.pageSize,search:S.search});
        const r=await fetch(`/api/servers?${p}`);const d=await r.json();
        if(!d.success)throw new Error(d.error);
        S.currentServers=d.items;S.pagination=d.pagination;
        renderServers(d.items);
        $('serverStats').textContent=`共 ${d.pagination.total} 台`;
        $('statServers')&&($('statServers').textContent=d.pagination.total);
        $('paginationInfo').textContent=d.pagination.total?`第 ${d.pagination.page} / ${d.pagination.pages} 页`:'暂无';
        $('prevPageBtn').disabled=S.page<=1;
        $('nextPageBtn').disabled=!d.pagination.pages||S.page>=d.pagination.pages;
    }catch(e){tbody.innerHTML=`<tr><td colspan="7" class="empty-state">加载失败：${esc(e.message)}</td></tr>`}
}
function renderServers(servers){
    const tbody=$('serverTableBody');
    if(!servers.length){tbody.innerHTML='<tr><td colspan="7" class="empty-state">没有匹配的服务器</td></tr>';return}
    const tm={idle:'单机同步',running:'同步中',success:'已成功',error:'已失败'};
    tbody.innerHTML=servers.map(s=>{
        const st=S.syncStates[s.id]||'idle';
        return `<tr>
            <td>${esc(s.host)}</td><td>${esc(s.port)}</td><td>${esc(s.group_name||'default')}</td>
            <td>${esc(s.remark||'-')}</td>
            <td><span class="chip ${s.enabled?'enabled':'disabled'}">${s.enabled?'启用':'禁用'}</span></td>
            <td>${esc(s.updated_at||'-')}</td>
            <td><div class="table-actions">
                <button class="sync-btn${st!=='idle'?' '+st:''}" data-sync-server-id="${s.id}" data-enabled="${s.enabled}" onclick="syncSingle(${s.id})" ${s.enabled&&st!=='running'?'':'disabled'}>${tm[st]||'单机同步'}</button>
                <button class="btn-secondary btn-sm" onclick="probeRemote(${s.id})" ${s.enabled?'':'disabled'}>探测到期</button>
                <button class="btn-secondary btn-sm" onclick="editServer(${s.id})">编辑</button>
                <button class="btn-danger btn-sm" onclick="removeServer(${s.id})">删除</button>
            </div></td></tr>`}).join('');
}
function setSyncState(id,status){
    S.syncStates[id]=status;
    const btn=document.querySelector(`[data-sync-server-id="${id}"]`);if(!btn)return;
    btn.className='sync-btn';if(status!=='idle')btn.classList.add(status);
    const m={idle:'单机同步',running:'同步中',success:'已成功',error:'已失败'};
    btn.textContent=m[status]||'单机同步';
    btn.disabled=status==='running'||btn.dataset.enabled!=='true';
}
function resetForm(){
    S.editingId=null;$('serverId').value='';$('serverHost').value='';$('serverPort').value='22';
    $('serverGroup').value='default';$('serverRemark').value='';$('serverEnabled').value='true';
    $('editorTitle').textContent='新增服务器';
}
function fillForm(s){
    S.editingId=s.id;$('serverId').value=s.id;$('serverHost').value=s.host;
    $('serverPort').value=s.port;$('serverGroup').value=s.group_name||'default';
    $('serverRemark').value=s.remark||'';$('serverEnabled').value=String(s.enabled);
    $('editorTitle').textContent=`编辑服务器 #${s.id}`;
}
window.editServer=function(id){
    const s=S.currentServers.find(x=>x.id===id);
    if(s){
        fillForm(s);
        /* 自动滚动到编辑表单 */
        $('editorTitle').scrollIntoView({behavior:'smooth',block:'start'});
    }
}
window.removeServer=async function(id){
    if(!confirm('确认删除？'))return;
    try{const r=await fetch(`/api/servers/${id}`,{method:'DELETE'});const d=await r.json();
    if(!d.success)throw new Error(d.error);if(S.editingId===id)resetForm();delete S.syncStates[id];
    showMsg($('serverMessage'),'已删除');if(S.page>1&&S.currentServers.length===1)S.page--;await loadServers();
    }catch(e){showMsg($('serverMessage'),e.message,'error')}
}
window.syncSingle=async function(id){
    const domain=getSelectedDomain();
    if(!domain){logStart('单机同步','');logAdd('请先在上方选择证书域名','error');logFinish('error','缺少域名');return}
    const s=S.currentServers.find(x=>x.id===id);if(!s)return;
    setSyncState(id,'running');logStart('单机同步',`${s.host}:${s.port}`);
    logAdd(`同步 ${domain} → ${s.host}:${s.port}`,'info','TASK');
    const fd=new FormData();fd.append('domain',domain);
    try{const r=await fetch(`/api/servers/${id}/sync`,{method:'POST',body:fd});
    await consumeStream(r,{onOk:()=>setSyncState(id,'success'),onFail:()=>setSyncState(id,'error'),okText:`${s.host}:${s.port} 同步完成`,failPre:'同步失败：'});
    }catch(e){setSyncState(id,'error');logAdd(`错误：${e.message}`,'error');logFinish('error','网络异常')}
}
window.probeRemote=async function(id){
    const domain=getSelectedDomain();if(!domain){logStart('证书探测','');logAdd('请先在上方选择证书域名','error');logFinish('error','');return}
    const s=S.currentServers.find(x=>x.id===id);if(!s)return;
    logStart('证书探测',`${s.host}:${s.port}`);logAdd(`探测 ${s.host}:${s.port} 上的 ${domain}`,'info','TASK');
    try{const r=await fetch(`/api/servers/${id}/remote-cert-info?domain=${encodeURIComponent(domain)}`);const d=await r.json();
    if(!r.ok||!d.success){logAdd(d.error||'探测失败','error','FAIL');logFinish('error',d.error||'');return}
    logAdd(`路径：${d.remote_cert}`,'info','PATH');logAdd(`到期：${d.expiry_date}`,'ok','CERT');
    logAdd(fmtDays(d.days_left),d.days_left<7?'warn':'ok','TIME');logFinish('success',`${s.host} ${fmtDays(d.days_left)}`);
    }catch(e){logAdd(`错误：${e.message}`,'error');logFinish('error','网络异常')}
}
/* 全部探测：遍历所有已启用服务器探测远端证书 */
async function probeAll(){
    const domain=getSelectedDomain();
    if(!domain){logStart('全部探测','');logAdd('请先在上方选择证书域名','error');logFinish('error','缺少域名');return}
    const btn=$('probeAllBtn');btn.disabled=true;btn.textContent='探测中...';
    logStart('全部探测',`域名：${domain}`);
    logAdd(`开始探测所有已启用服务器上的 ${domain} 证书`,'info','TASK');
    /* 获取全量已启用服务器 */
    let allServers=[];
    try{
        const r=await fetch('/api/servers?page=1&page_size=9999&search=');const d=await r.json();
        if(!d.success)throw new Error(d.error);
        allServers=d.items.filter(s=>s.enabled);
    }catch(e){logAdd(`加载服务器列表失败：${e.message}`,'error');logFinish('error','加载失败');btn.disabled=false;btn.textContent='全部探测';return}
    if(!allServers.length){logAdd('没有已启用的服务器','warn');logFinish('error','无可探测节点');btn.disabled=false;btn.textContent='全部探测';return}
    logAdd(`共 ${allServers.length} 台已启用服务器`,'info');
    let ok=0,fail=0;
    for(const s of allServers){
        logAdd(`探测 ${s.host}:${s.port} (${s.remark||s.group_name})`,'info','PING');
        try{
            const r=await fetch(`/api/servers/${s.id}/remote-cert-info?domain=${encodeURIComponent(domain)}`);
            const d=await r.json();
            if(!r.ok||!d.success){logAdd(`  ✗ ${s.host}:${s.port} — ${d.error||'探测失败'}`,'error','FAIL');fail++;continue}
            const cls=d.days_left<7?'warn':d.days_left<30?'warn':'ok';
            logAdd(`  ✓ ${s.host}:${s.port} — ${fmtDays(d.days_left)} (${d.expiry_date})`,cls,'CERT');
            ok++;
        }catch(e){logAdd(`  ✗ ${s.host}:${s.port} — 网络错误：${e.message}`,'error','FAIL');fail++}
    }
    logAdd(`探测完成：成功 ${ok} / 失败 ${fail} / 共 ${allServers.length}`,'info','DONE');
    logFinish(fail?'error':'success',`成功 ${ok} 台，失败 ${fail} 台`);
    btn.disabled=false;btn.textContent='全部探测';
}
async function saveServer(e){
    e.preventDefault();clearMsg($('serverMessage'));
    const payload={host:$('serverHost').value.trim(),port:Number($('serverPort').value),
        group_name:$('serverGroup').value.trim(),remark:$('serverRemark').value.trim(),enabled:$('serverEnabled').value==='true'};
    const isEdit=Boolean(S.editingId);
    try{const r=await fetch(isEdit?`/api/servers/${S.editingId}`:'/api/servers',{method:isEdit?'PUT':'POST',
        headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
    const d=await r.json();if(!d.success)throw new Error(d.error);
    showMsg($('serverMessage'),isEdit?'已更新':'已创建');resetForm();await loadServers();
    }catch(e){showMsg($('serverMessage'),e.message,'error')}
}

/* ===== 证书同步 ===== */
function updateMode(mode){
    S.mode=mode;$('specificTargets').classList.toggle('hidden',mode!=='specific');
    document.querySelectorAll('.radio-option').forEach(o=>{const r=o.querySelector('input');o.classList.toggle('active',r.value===mode)});
}
async function submitSync(e){
    e.preventDefault();const domain=$('domain').value;
    if(!domain){logStart('同步','');logAdd('请选择域名','error');logFinish('error','');return}
    const fd=new FormData();fd.append('domain',domain);fd.append('target_mode',S.mode);
    if(S.mode==='specific'){const v=$('specific_ips').value.trim();if(!v){logStart('同步','');logAdd('请填写目标','error');logFinish('error','');return}fd.append('specific_ips',v)}
    const btn=$('submitBtn');btn.disabled=true;btn.textContent='同步中...';
    logStart(S.mode==='all'?'全量同步':'临时目标同步','');logAdd(`同步 ${domain}`,'info','TASK');
    try{const r=await fetch('/sync',{method:'POST',body:fd});
    await consumeStream(r,{onOk:null,onFail:null,okText:'同步完成',failPre:'失败：'});
    }catch(e){logAdd(`错误：${e.message}`,'error');logFinish('error','网络异常')}
    finally{btn.disabled=false;btn.textContent='开始同步'}
}

/* ===== 账号安全 ===== */
async function updatePassword(e){
    e.preventDefault();const msg=$('passwordMessage');clearMsg(msg);
    try{const r=await fetch('/api/account/password',{method:'POST',headers:{'Content-Type':'application/json'},
        body:JSON.stringify({current_password:$('currentPassword').value,new_password:$('newPassword').value,confirm_password:$('confirmPassword').value})});
    const d=await r.json();if(!d.success)throw new Error(d.error);
    $('currentPassword').value='';$('newPassword').value='';$('confirmPassword').value='';
    showMsg(msg,'密码已更新');
    }catch(e){showMsg(msg,e.message,'error')}
}

/* 2FA */
function update2FAStatus(enabled){
    const b=$('twoFactorBadge');b.className=`status-badge ${enabled?'enabled':'disabled'}`;b.textContent=enabled?'已启用':'未启用';
    $('twoFactorDisableForm').classList.toggle('hidden',!enabled);
    $('twoFactorSetupForm').classList.toggle('hidden',enabled);
    if(enabled)$('twoFactorSetupPanel').classList.add('hidden');
}
async function loadTwoFactorStatus(){
    try{const r=await fetch('/api/account/2fa/status');const d=await r.json();
    if(d.success)update2FAStatus(Boolean(d.enabled));
    }catch(e){}
}
async function startTwoFactorSetup(e){
    e.preventDefault();const msg=$('twoFactorMessage');clearMsg(msg);
    try{const r=await fetch('/api/account/2fa/setup',{method:'POST',headers:{'Content-Type':'application/json'},
        body:JSON.stringify({current_password:$('twoFactorCurrentPassword').value})});
    const d=await r.json();if(!d.success)throw new Error(d.error);
    $('twoFactorSecret').textContent=d.secret;$('twoFactorUri').textContent=d.otpauth_uri;
    $('twoFactorSetupPanel').classList.remove('hidden');$('twoFactorOtpCode').value='';
    showMsg(msg,'密钥已生成，请在认证器中绑定后输入验证码确认。');
    }catch(e){showMsg(msg,e.message,'error')}
}
async function enableTwoFactor(e){
    e.preventDefault();const msg=$('twoFactorMessage');clearMsg(msg);
    try{const r=await fetch('/api/account/2fa/enable',{method:'POST',headers:{'Content-Type':'application/json'},
        body:JSON.stringify({current_password:$('twoFactorCurrentPassword').value,otp_code:$('twoFactorOtpCode').value})});
    const d=await r.json();if(!d.success)throw new Error(d.error);
    $('twoFactorCurrentPassword').value='';$('twoFactorOtpCode').value='';
    $('twoFactorSecret').textContent='';$('twoFactorUri').textContent='';
    $('twoFactorSetupPanel').classList.add('hidden');update2FAStatus(true);
    showMsg(msg,'2FA 已启用');
    }catch(e){showMsg(msg,e.message,'error')}
}
async function disableTwoFactor(e){
    e.preventDefault();const msg=$('twoFactorMessage');clearMsg(msg);
    try{const r=await fetch('/api/account/2fa/disable',{method:'POST',headers:{'Content-Type':'application/json'},
        body:JSON.stringify({current_password:$('twoFactorDisablePassword').value,otp_code:$('twoFactorDisableCode').value})});
    const d=await r.json();if(!d.success)throw new Error(d.error);
    $('twoFactorDisablePassword').value='';$('twoFactorDisableCode').value='';
    update2FAStatus(false);showMsg(msg,'2FA 已关闭');
    }catch(e){showMsg(msg,e.message,'error')}
}

/* Passkey */
function updatePasskeyBadge(n){const b=$('passkeyBadge');b.className=`status-badge ${n>0?'enabled':'disabled'}`;b.textContent=n>0?`已配置 ${n} 个`:'未配置'}
function renderPasskeys(items){
    const list=$('passkeyList');
    if(!items.length){list.innerHTML='<div class="empty-state">还没有注册 Passkey。</div>';updatePasskeyBadge(0);return}
    list.innerHTML=items.map(i=>`<div class="passkey-item"><div class="passkey-item-head"><strong>${esc(i.label||'未命名')}</strong><button class="btn-danger btn-sm" data-passkey-id="${i.id}">删除</button></div><div class="passkey-meta">凭据 ID：${esc(i.credential_id)}</div><div class="passkey-meta">创建：${esc(i.created_at||'-')} · 最近使用：${esc(i.last_used_at||'尚未使用')}</div></div>`).join('');
    updatePasskeyBadge(items.length);
}
async function loadPasskeys(){
    try{const r=await fetch('/api/account/passkeys');const d=await r.json();
    if(d.success)renderPasskeys(d.items||[]);
    }catch(e){$('passkeyList').innerHTML=`<div class="empty-state">${esc(e.message)}</div>`;updatePasskeyBadge(0)}
}
async function registerPasskey(e){
    e.preventDefault();const msg=$('passkeyMessage');clearMsg(msg);
    if(!window.PublicKeyCredential){showMsg(msg,'浏览器不支持 Passkey','error');return}
    try{
        const oR=await fetch('/api/account/passkeys/register/options',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});
        const oD=await oR.json();if(!oD.success)throw new Error(oD.error);
        const pk=oD.publicKey;pk.challenge=b64UrlToBuf(pk.challenge);pk.user.id=b64UrlToBuf(pk.user.id);
        pk.excludeCredentials=(pk.excludeCredentials||[]).map(i=>({...i,id:b64UrlToBuf(i.id)}));
        const cred=await navigator.credentials.create({publicKey:pk});
        const payload={id:cred.id,type:cred.type,rawId:bufToB64Url(cred.rawId),label:$('passkeyLabel').value.trim(),
            response:{clientDataJSON:bufToB64Url(cred.response.clientDataJSON),attestationObject:bufToB64Url(cred.response.attestationObject)},
            transports:cred.response.getTransports?cred.response.getTransports():[]};
        const vR=await fetch('/api/account/passkeys/register/verify',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
        const vD=await vR.json();if(!vD.success)throw new Error(vD.error);
        $('passkeyLabel').value='';showMsg(msg,'Passkey 已注册');await loadPasskeys();
    }catch(e){showMsg(msg,e.message,'error')}
}
async function deletePasskey(id){
    const msg=$('passkeyMessage');clearMsg(msg);
    try{const r=await fetch(`/api/account/passkeys/${id}`,{method:'DELETE'});const d=await r.json();
    if(!d.success)throw new Error(d.error);showMsg(msg,'已删除');await loadPasskeys();
    }catch(e){showMsg(msg,e.message,'error')}
}

/* ===== 初始化绑定 ===== */
document.addEventListener('DOMContentLoaded',function(){
    initTheme();resetForm();updateMode('all');
    // 导航
    document.querySelectorAll('.nav-item,.tab-item').forEach(n=>n.addEventListener('click',()=>switchView(n.dataset.view)));
    // 主题
    const ts=$('themeSelect');if(ts)ts.addEventListener('change',e=>{localStorage.setItem('theme-preference',e.target.value);applyTheme(e.target.value)});
    // 服务器表单
    $('serverForm').addEventListener('submit',saveServer);
    $('resetServerBtn').addEventListener('click',()=>{resetForm();clearMsg($('serverMessage'))});
    // 搜索分页
    $('searchBtn').addEventListener('click',async()=>{S.search=$('searchInput').value.trim();S.page=1;await loadServers()});
    $('resetSearchBtn').addEventListener('click',async()=>{$('searchInput').value='';S.search='';S.page=1;await loadServers()});
    $('pageSizeSelect').addEventListener('change',async()=>{S.pageSize=Number($('pageSizeSelect').value);S.page=1;await loadServers()});
    $('prevPageBtn').addEventListener('click',async()=>{if(S.page>1){S.page--;await loadServers()}});
    $('nextPageBtn').addEventListener('click',async()=>{if(S.pagination.pages&&S.page<S.pagination.pages){S.page++;await loadServers()}});
    // 同步
    $('syncForm').addEventListener('submit',submitSync);
    $('refreshDomains').addEventListener('click',loadDomains);
    $('probeAllBtn')?.addEventListener('click',probeAll);
    $('refreshServerDomains')?.addEventListener('click',loadServerDomains);
    document.querySelectorAll('input[name="target_mode"]').forEach(r=>r.addEventListener('change',e=>updateMode(e.target.value)));
    // 账号
    $('passwordForm').addEventListener('submit',updatePassword);
    $('twoFactorSetupForm').addEventListener('submit',startTwoFactorSetup);
    $('twoFactorEnableForm').addEventListener('submit',enableTwoFactor);
    $('twoFactorDisableForm').addEventListener('submit',disableTwoFactor);
    $('passkeyRegisterForm').addEventListener('submit',registerPasskey);
    $('passkeyList').addEventListener('click',e=>{const b=e.target.closest('[data-passkey-id]');if(b)deletePasskey(b.dataset.passkeyId)});
    // 快捷跳转
    $('goSync')?.addEventListener('click',()=>switchView('sync'));
    $('goServers')?.addEventListener('click',()=>switchView('servers'));
    // 默认视图
    switchView('dashboard');
});
