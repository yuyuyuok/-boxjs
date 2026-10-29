// 领克签到 · BoxJs + Loon 移植版（基于 lynk_sign_docker 的核心流程）
// 使用：在 BoxJs 配置 lynk_refresh_token / lynk_device_id；Loon 中作为定时脚本运行。
// 注意：首次版本只实现主账号 refresh + 状态查询 + 日常签到 + 基础账户信息。
// 自动分享、多渠道推送暂不启用，避免未经验证的多账号操作。

const STORE_RT = "lynk_refresh_token";
const STORE_DEVICE = "lynk_device_id";
const STORE_AT = "lynk_access_token";
const STORE_AT_EXP = "lynk_access_expire_at";
const STORE_AT_RT = "lynk_access_refresh_source";

const API_BASE = "https://app-api-gw-toc.lynkco.com";
const OAUTH_BASE = "https://app-services.lynkco.com.cn";
const REFRESH_URL = OAUTH_BASE + "/auth/login/refresh";
const CA_KEY = "204644386";
const CA_SECRET = "QCl7udM3PB9cOIOwquwPglikFQnzJRsX";
const APP_CODE = "3fa3314998bd4195a9fe2df3e85e6a12";
const EP_SIGN = "/up/api/v1/user/sign";
const EP_SIGN_INFO = "/up/api/v1/userReward/getContinueDaysAndSignCard";
const EP_ENERGY = "/app/energy/myEnergy";
const EP_GROWTH = "/app/energy/my/growth";
const EP_TASKS = "/up/api/v1/userReward/getTaskList";

function log(s) { console.log("[领克签到] " + s); }
function doneNotice(title, message) {
  try { $notification.post(title, "领克签到", message); } catch (_) {}
}
function utf8(s) {
  const encoded = unescape(encodeURIComponent(String(s)));
  const out = [];
  for (let i = 0; i < encoded.length; i++) out.push(encoded.charCodeAt(i));
  return out;
}
function rotr(x, n) { return (x >>> n) | (x << (32 - n)); }
function sha256Bytes(bytes) {
  const K = [
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
  ];
  let m = bytes.slice();
  const bitLen = m.length * 8;
  m.push(0x80);
  while ((m.length % 64) !== 56) m.push(0);
  const hi = Math.floor(bitLen / 0x100000000), lo = bitLen >>> 0;
  for (let i=3;i>=0;i--) m.push((hi >>> (i*8)) & 255);
  for (let i=3;i>=0;i--) m.push((lo >>> (i*8)) & 255);
  let H = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
  for (let off=0; off<m.length; off+=64) {
    const w = new Array(64);
    for (let i=0;i<16;i++) {
      const j=off+i*4; w[i]=((m[j]<<24)|(m[j+1]<<16)|(m[j+2]<<8)|m[j+3])>>>0;
    }
    for (let i=16;i<64;i++) {
      const x=w[i-15], y=w[i-2];
      const s0=rotr(x,7)^rotr(x,18)^(x>>>3);
      const s1=rotr(y,17)^rotr(y,19)^(y>>>10);
      w[i]=(w[i-16]+s0+w[i-7]+s1)>>>0;
    }
    let [a,b,c,d,e,f,g,h]=H;
    for (let i=0;i<64;i++) {
      const S1=rotr(e,6)^rotr(e,11)^rotr(e,25);
      const ch=(e&f)^(~e&g);
      const t1=(h+S1+ch+K[i]+w[i])>>>0;
      const S0=rotr(a,2)^rotr(a,13)^rotr(a,22);
      const maj=(a&b)^(a&c)^(b&c);
      const t2=(S0+maj)>>>0;
      h=g; g=f; f=e; e=(d+t1)>>>0; d=c; c=b; b=a; a=(t1+t2)>>>0;
    }
    H=H.map((v,i)=>(v+[a,b,c,d,e,f,g,h][i])>>>0);
  }
  const out=[];
  H.forEach(v=>{out.push((v>>>24)&255,(v>>>16)&255,(v>>>8)&255,v&255);});
  return out;
}
function hmacSha256(keyText, msgText) {
  let key=utf8(keyText), msg=utf8(msgText);
  if (key.length>64) key=sha256Bytes(key);
  while(key.length<64) key.push(0);
  const inner=key.map(x=>x^0x36).concat(msg);
  const outer=key.map(x=>x^0x5c).concat(sha256Bytes(inner));
  return sha256Bytes(outer);
}
function base64(bytes) {
  const chars="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  let out="";
  for(let i=0;i<bytes.length;i+=3) {
    const a=bytes[i], hasB=i+1<bytes.length, hasC=i+2<bytes.length;
    const b=hasB?bytes[i+1]:0, c=hasC?bytes[i+2]:0;
    out+=chars[a>>2]+chars[((a&3)<<4)|(b>>4)];
    out+=hasB?chars[((b&15)<<2)|(c>>6)]:"=";
    out+=hasC?chars[c&63]:"=";
  }
  return out;
}
function randomNonce() {
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, c => {
    const r=Math.floor(Math.random()*16);
    return (c==="x"?r:((r&3)|8)).toString(16);
  }).toUpperCase();
}
function encodeQuery(params) {
  return Object.keys(params).sort().map(k=>encodeURIComponent(k)+"="+encodeURIComponent(String(params[k]))).join("&");
}
function signedHeaders(method, path, params) {
  const ts=String(Date.now()), nonce=randomNonce();
  const h={
    "X-Ca-Key":CA_KEY,
    "X-Ca-Nonce":nonce,
    "X-Ca-Signature-Method":"HmacSHA256",
    "X-Ca-Timestamp":ts
  };
  let url=path;
  if(params && Object.keys(params).length) url += "?" + encodeQuery(params);
  const parts=[method.toUpperCase(),"*/*","","application/json",""];
  // 顺序与原 Python 项目 build_sig() 保持一致
  ["X-Ca-Key","X-Ca-Nonce","X-Ca-Signature-Method","X-Ca-Timestamp"].forEach(k=>parts.push(k+":"+h[k]));
  parts.push(url);
  h["X-Ca-Signature-Headers"]="X-Ca-Key,X-Ca-Timestamp,X-Ca-Nonce,X-Ca-Signature-Method";
  h["X-Ca-Signature"]=base64(hmacSha256(CA_SECRET,parts.join("\n")));
  h["Accept"]="*/*";
  return h;
}
function request(method, url, headers, body) {
  return new Promise((resolve,reject)=>{
    const opt={url:url,headers:headers||{},timeout:20000};
    if(body!==undefined) opt.body=typeof body==="string"?body:JSON.stringify(body);
    $httpClient[method.toLowerCase()](opt,(err,resp,data)=>{
      if(err) return reject(new Error(String(err)));
      let parsed;
      try { parsed=JSON.parse(data); } catch (_) { parsed={code:resp?resp.status:"?",raw:String(data||"").slice(0,400)}; }
      resolve({status:resp?resp.status:0,data:parsed});
    });
  });
}
async function refreshToken(rt, deviceId) {
  const params={refreshToken:rt,deviceId:deviceId,deviceType:"IOS",appVersion:"4.2.0"};
  const url=REFRESH_URL+"?"+encodeQuery(params);
  const headers={
    "Authorization":"APPCODE "+APP_CODE,
    "accept":"application/json",
    "content-type":"application/json; charset=UTF-8",
    "publicplatform":"iOS",
    "user-agent":"CA_iOS_SDK_2.0",
    "token":"",
    "gl_dev_id":deviceId,
    "appversioncode":"4.2.0",
    "appversionname":"40200106",
    "gl_app_version":"4.2.0",
    "gl_app_build":"40200106",
    "x-ca-version":"1"
  };
  const r=await request("GET",url,headers);
  const j=r.data||{};
  if(j.code!=="success") throw new Error("Token 刷新失败: "+(j.message||JSON.stringify(j).slice(0,180)));
  const dto=((j.data||{}).centerTokenDto)||{};
  if(!dto.token) throw new Error("刷新接口未返回 accessToken");
  if(dto.refreshToken) $persistentStore.write(dto.refreshToken,STORE_RT);
  const exp=Date.parse(dto.expireAt||"");
  $persistentStore.write(dto.token,STORE_AT);
  $persistentStore.write(String(exp||Date.now()+8*60*1000),STORE_AT_EXP);
  return dto.token;
}
async function api(method,path,token,body,params) {
  const query=params && Object.keys(params).length ? "?"+encodeQuery(params) : "";
  const headers=Object.assign({"token":token,"content-type":"application/json"},signedHeaders(method,path,params));
  const r=await request(method,API_BASE+path+query,headers,body);
  return r.data;
}
function ok(j) { return j && (String(j.code)==="200" || String(j.code)==="success"); }

async function main() {
  const rt=String($persistentStore.read(STORE_RT)||"").trim();
  const deviceId=String($persistentStore.read(STORE_DEVICE)||"").trim();
  if(!rt || !deviceId) {
    const msg="请先在 BoxJs 中填写 refresh_token 和 device_id，再运行脚本。";
    log(msg); doneNotice("配置未完成",msg); return;
  }
  log("开始执行；refreshToken 尾号："+rt.slice(-8));
  let token;
  try {
    const cached=String($persistentStore.read(STORE_AT)||"");
    const exp=Number($persistentStore.read(STORE_AT_EXP)||0);
    if(cached && exp>Date.now()+60000) {
      token=cached;
      log("使用本地 accessToken 缓存");
    } else {
      token=await refreshToken(rt,deviceId);
      log("accessToken 刷新成功；refreshToken 如发生轮换已写回 BoxJs 存储");
    }
  } catch(e) {
    throw new Error("获取 accessToken 失败："+e.message);
  }

  const info=await api("GET",EP_SIGN_INFO,token);
  if(!ok(info)) throw new Error("查询签到状态失败："+JSON.stringify(info).slice(0,220));
  const d=info.data||{};
  const signStatus=d.signStatus||d.todaySigned||d.status;
  const streak=d.continuousSignDays||d.serialDays||d.continueDays||0;
  const signCard=d.signCardNumber||0;
  let signText="今日已签到", reward="无新增";
  if(!(signStatus===1 || signStatus===true || signStatus==="1" || signStatus==="signed" || signStatus==="already")) {
    const result=await api("POST",EP_SIGN,token,{});
    if(!ok(result)) throw new Error("签到请求失败："+JSON.stringify(result).slice(0,220));
    signText="签到成功";
    const rd=result.data||{};
    const parts=[];
    if(rd.rewardEnergyNumber) parts.push("+"+rd.rewardEnergyNumber+" 能量体");
    if(rd.rewardPointNumber) parts.push("+"+rd.rewardPointNumber+" Co积分");
    if(rd.rewardSignCardNumber) parts.push("+"+rd.rewardSignCardNumber+" 补签卡");
    reward=parts.join("、")||"接口未返回奖励字段";
  }

  let energy="-", income="-", level="-", growth="-";
  try {
    const e=await api("GET",EP_ENERGY,token);
    if(ok(e)){energy=(e.data||{}).point??"-";income=(e.data||{}).incomePoint??"-";}
  } catch(e){log("能量信息查询异常："+e.message);}
  try {
    const g=await api("GET",EP_GROWTH,token);
    if(ok(g)){const lv=((g.data||{}).accountLevelVo)||{};level=lv.name||"-";growth=lv.growth??"-";}
  } catch(e){log("成长值查询异常："+e.message);}
  let taskLines=[];
  try {
    const t=await api("GET",EP_TASKS,token);
    if(ok(t) && Array.isArray(t.data)) taskLines=t.data.map(x=>(x.taskName||"任务")+": "+(x.taskProcess??"?")+"（"+((x.rewardContent||[]).join("、")||"奖励未提供")+"）");
  } catch(e){log("任务进度查询异常："+e.message);}

  const message=signText+"；奖励："+reward+"；连续签到："+streak+" 天；补签卡："+signCard+" 张；能量体："+energy+"；累计获得："+income+"；等级："+level+"；成长值："+growth;
  log(message);
  taskLines.forEach(x=>log(x));
  doneNotice("领克签到完成",message);
}
main().then(()=>{$done();}).catch(e=>{
  log("失败："+e.message);
  doneNotice("领克签到失败",e.message);
  $done();
});
