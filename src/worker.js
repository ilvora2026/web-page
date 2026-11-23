const COOKIE = "__Host-ilvora_session";
const SESSION_HOURS = 8;
// Cloudflare Workers WebCrypto currently caps PBKDF2 at 100,000 iterations.
// Keep this value within the runtime limit; verification uses the stored iteration count.
const PBKDF2_ITERATIONS = 100000;
const ROLES = new Set([
  "managing_director","administrator","head_office_admin",
  "branch_admin","employee","attendance_marker"
]);

function json(data, status=200, headers={}) {
  return new Response(JSON.stringify(data), {
    status, headers: {"content-type":"application/json; charset=utf-8","cache-control":"no-store",...headers}
  });
}
function cookieValue(request, name) {
  const raw=request.headers.get("Cookie")||"";
  for (const part of raw.split(";")) {
    const i=part.indexOf("=");
    if (i>0 && part.slice(0,i).trim()===name) return part.slice(i+1).trim();
  }
  return null;
}
function b64(bytes) {
  let s=""; for (const b of new Uint8Array(bytes)) s+=String.fromCharCode(b);
  return btoa(s).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
}
function unb64(s) {
  s=s.replace(/-/g,"+").replace(/_/g,"/");
  while(s.length%4) s+="=";
  const raw=atob(s); return Uint8Array.from(raw,c=>c.charCodeAt(0));
}
async function sha256(value) {
  return b64(await crypto.subtle.digest("SHA-256",new TextEncoder().encode(value)));
}
async function makePasswordHash(password) {
  const salt=crypto.getRandomValues(new Uint8Array(16));
  const key=await crypto.subtle.importKey("raw",new TextEncoder().encode(password),"PBKDF2",false,["deriveBits"]);
  const bits=await crypto.subtle.deriveBits({name:"PBKDF2",salt,iterations:PBKDF2_ITERATIONS,hash:"SHA-256"},key,256);
  return `pbkdf2$${PBKDF2_ITERATIONS}$${b64(salt)}$${b64(bits)}`;
}
async function verifyPassword(password, stored) {
  try {
    const [scheme,iterations,salt,expected]=stored.split("$");
    if(scheme!=="pbkdf2" || !iterations || !salt || !expected) return false;
    const key=await crypto.subtle.importKey("raw",new TextEncoder().encode(password),"PBKDF2",false,["deriveBits"]);
    const bits=await crypto.subtle.deriveBits({name:"PBKDF2",salt:unb64(salt),iterations:Number(iterations),hash:"SHA-256"},key,256);
    return b64(bits)===expected;
  } catch { return false; }
}
function safeUser(row) {
  return {id:row.id,username:row.username,display_name:row.display_name,role:row.role,branch_id:row.branch_id,status:row.status,must_change_password:!!row.must_change_password};
}
async function audit(env, actor, action, targetType=null, targetId=null, details=null, request=null) {
  await env.DB.prepare(`INSERT INTO audit_events
    (id,actor_user_id,actor_role,branch_id,action,target_type,target_id,details_json,ip_address)
    VALUES(?,?,?,?,?,?,?,?,?)`)
    .bind(crypto.randomUUID(),actor?.id||null,actor?.role||null,actor?.branch_id||null,
      action,targetType,targetId,details?JSON.stringify(details):null,
      request?.headers.get("CF-Connecting-IP")||null).run();
}
async function currentUser(request, env) {
  const raw=cookieValue(request,COOKIE);
  if(!raw) return null;
  const tokenHash=await sha256(raw);
  const row=await env.DB.prepare(`SELECT u.*,s.id AS session_id,s.expires_at
    FROM sessions s JOIN users u ON u.id=s.user_id
    WHERE s.token_hash=? AND s.expires_at>? AND u.status='active'`)
    .bind(tokenHash,new Date().toISOString()).first();
  if(!row) return null;
  await env.DB.prepare("UPDATE sessions SET last_seen_at=CURRENT_TIMESTAMP WHERE id=?").bind(row.session_id).run();
  return {...row,session_id:row.session_id};
}
function cookie(token, maxAge) {
  return `${COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`;
}
function clearCookie() {
  return `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;
}
function sameOrigin(request) {
  const origin=request.headers.get("Origin");
  if(!origin) return true;
  try { return new URL(origin).host===new URL(request.url).host; } catch { return false; }
}
async function bodyJson(request) {
  const type=request.headers.get("content-type")||"";
  if(!type.includes("application/json")) throw new Error("Content-Type must be application/json");
  return await request.json();
}
async function requireUser(request,env) {
  const user=await currentUser(request,env);
  if(!user) return {error:json({error:"Authentication required"},401)};
  return {user};
}
function canManageUsers(role) {
  return ["managing_director","administrator","head_office_admin","branch_admin"].includes(role);
}
function canCreateRole(actorRole,targetRole) {
  const allowed={
    managing_director:["administrator","head_office_admin","branch_admin","employee","attendance_marker"],
    administrator:["head_office_admin","branch_admin","employee","attendance_marker"],
    head_office_admin:["branch_admin","employee","attendance_marker"],
    branch_admin:["employee","attendance_marker"]
  };
  return (allowed[actorRole]||[]).includes(targetRole);
}
function validPassword(p) {
  return typeof p==="string" && p.length>=12 && p.length<=128 &&
    /[a-z]/.test(p) && /[A-Z]/.test(p) && /\d/.test(p);
}
function randomToken(length=32) {
  const alphabet="ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%*-_";
  const bytes=crypto.getRandomValues(new Uint8Array(length));
  return Array.from(bytes,b=>alphabet[b%alphabet.length]).join("");
}
function randomOtp() {
  const a=new Uint32Array(1); crypto.getRandomValues(a); return String(a[0]%1000000).padStart(6,"0");
}
async function sendEmail(env,to,subject,textBody) {
  if(!env.RESEND_API_KEY || !env.EMAIL_FROM) throw new Error("Email delivery provider is not configured");
  const r=await fetch("https://api.resend.com/emails",{method:"POST",headers:{"Authorization":`Bearer ${env.RESEND_API_KEY}`,"Content-Type":"application/json"},body:JSON.stringify({from:env.EMAIL_FROM,to:[to],subject,text:textBody})});
  if(!r.ok) throw new Error("Email delivery failed");
}
async function sendSms(env,to,message) {
  if(!env.TWILIO_ACCOUNT_SID || !env.TWILIO_AUTH_TOKEN || !env.TWILIO_FROM_NUMBER) throw new Error("SMS delivery provider is not configured");
  const auth=btoa(`${env.TWILIO_ACCOUNT_SID}:${env.TWILIO_AUTH_TOKEN}`);
  const form=new URLSearchParams({To:to,From:env.TWILIO_FROM_NUMBER,Body:message});
  const r=await fetch(`https://api.twilio.com/2010-04-01/Accounts/${env.TWILIO_ACCOUNT_SID}/Messages.json`,{method:"POST",headers:{Authorization:`Basic ${auth}`,"Content-Type":"application/x-www-form-urlencoded"},body:form});
  if(!r.ok) throw new Error("SMS delivery failed");
}
async function otpDigest(env,group,otp) {
  if(!env.OTP_PEPPER) throw new Error("OTP hashing secret is not configured");
  const key=await crypto.subtle.importKey("raw",new TextEncoder().encode(env.OTP_PEPPER),{name:"HMAC",hash:"SHA-256"},false,["sign"]);
  return b64(await crypto.subtle.sign("HMAC",key,new TextEncoder().encode(`${group}:${otp}`)));
}
async function createOtpPair(env,user,purpose,groupId=null) {
  const group=groupId||crypto.randomUUID();
  const emailOtp=randomOtp(),smsOtp=randomOtp(),expires=new Date(Date.now()+15*60*1000).toISOString(),resend=new Date(Date.now()+60*1000).toISOString();
  await env.DB.prepare("DELETE FROM otp_challenges WHERE user_id=? AND purpose=? AND consumed_at IS NULL").bind(user.id,purpose).run();
  await env.DB.prepare(`INSERT INTO otp_challenges(id,user_id,purpose,channel,otp_hash,expires_at,resend_after,challenge_group) VALUES(?,?,?,?,?,?,?,?),(?,?,?,?,?,?,?,?)`)
    .bind(crypto.randomUUID(),user.id,purpose,"email",await otpDigest(env,group,emailOtp),expires,resend,group,crypto.randomUUID(),user.id,purpose,"sms",await otpDigest(env,group,smsOtp),expires,resend,group).run();
  const maskedEmail=user.registered_email.replace(/^(.{1,2}).*(@.*)$/,"$1***$2"),maskedMobile=user.registered_mobile.replace(/.(?=.{4})/g,"•");
  try {
    await Promise.all([
      sendEmail(env,user.registered_email,"ILVORA Workforce verification code",`Your ILVORA Workforce OTP is ${emailOtp}. It expires in 15 minutes. Do not share this code.`),
      sendSms(env,user.registered_mobile,`ILVORA Workforce OTP: ${smsOtp}. Valid for 15 minutes. Do not share it.`)
    ]);
  } catch(e) {
    await env.DB.prepare("DELETE FROM otp_challenges WHERE challenge_group=?").bind(group).run();
    throw e;
  }
  return {challenge_id:group,expires_in_seconds:900,resend_after_seconds:60,delivery:{email:maskedEmail,mobile:maskedMobile}};
}
async function generateInitialPassword() { return randomToken(20)+"A1a"; }
function indiaDateKey(date=new Date()) {
  const parts=new Intl.DateTimeFormat("en-CA",{timeZone:"Asia/Kolkata",year:"numeric",month:"2-digit",day:"2-digit"}).formatToParts(date);
  const p=Object.fromEntries(parts.map(x=>[x.type,x.value])); return `${p.year}-${p.month}-${p.day}`;
}
async function attendanceState(env,user) {
  if(["managing_director","administrator"].includes(user.role)) return {required:false,marked:true,exempt:true};
  const date=indiaDateKey();
  const row=await env.DB.prepare(`SELECT id,created_at,data_json FROM workforce_records
    WHERE record_type='attendance' AND owner_user_id=? AND json_extract(data_json,'$.attendance_date')=? AND status<>'cancelled' LIMIT 1`)
    .bind(user.id,date).first();
  return {required:true,marked:!!row,attendance_date:date,record_id:row?.id||null,branch_id:user.branch_id||"branch_kochi"};
}
async function handleApi(request,env) {
  const url=new URL(request.url), path=url.pathname, method=request.method;
  if(path==="/api/health" && method==="GET") {
    const r=await env.DB.prepare("SELECT 1 AS ok").first();
    return json({ok:!!r,service:"ILVORA Workforce API",mode:"operational workspace foundation"});
  }
  if(!sameOrigin(request)) return json({error:"Cross-origin request denied"},403);

  if(path==="/api/setup/bootstrap" && method==="POST") {
    const existing=await env.DB.prepare("SELECT setting_value FROM app_settings WHERE setting_key='bootstrap_completed'").first();
    if(!env.BOOTSTRAP_SECRET || !existing || existing.setting_value!=="0") return json({error:"Bootstrap is unavailable or already completed"},403);
    const data=await bodyJson(request);
    if(data.secret!==env.BOOTSTRAP_SECRET) return json({error:"Invalid bootstrap secret"},403);
    const username=String(data.username||"").trim();
    const displayName=String(data.display_name||"").trim();
    const email=String(data.registered_email||"").trim().toLowerCase(),mobile=String(data.registered_mobile||"").trim();
    if(!/^[A-Za-z0-9._-]{4,40}$/.test(username) || !displayName || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !/^\+[1-9]\d{7,14}$/.test(mobile))
      return json({error:"Provide username, full name, registered email and mobile in international format (+countrycode)"},400);
    const exists=await env.DB.prepare("SELECT id FROM users WHERE role='managing_director' LIMIT 1").first();
    if(exists) return json({error:"Managing Director account already exists"},409);
    const password=await generateInitialPassword(),id=crypto.randomUUID(),hash=await makePasswordHash(password);
    await env.DB.prepare(`INSERT INTO users(id,username,display_name,password_hash,role,branch_id,must_change_password,registered_email,registered_mobile)
      VALUES(?,?,?,?,'managing_director',NULL,1,?,?)`).bind(id,username,displayName,hash,email,mobile).run();
    try { await sendEmail(env,email,"Your ILVORA Workforce initial Managing Director login",`Hello ${displayName},\n\nYour ILVORA Workforce username is ${username}.\nYour automatically generated initial password is: ${password}\n\nThis password remains valid until you change it at first login. Keep it confidential.`); }
    catch { await env.DB.prepare("DELETE FROM users WHERE id=?").bind(id).run(); return json({error:"Initial account not created because credentials could not be delivered. Check email provider configuration."},503); }
    await env.DB.prepare("UPDATE app_settings SET setting_value='1',updated_at=CURRENT_TIMESTAMP WHERE setting_key='bootstrap_completed'").run();
    await audit(env,{id,role:"managing_director",branch_id:null},"bootstrap.md_account_created","user",id,{credential_delivery:"email"},request);
    return json({ok:true,message:"Initial Managing Director account created. Initial password sent to registered email; remove BOOTSTRAP_SECRET after setup."},201);
  }

  if(path==="/api/auth/otp/request" && method==="POST") {
    const d=await bodyJson(request),username=String(d.username||"").trim(),email=String(d.email||"").trim().toLowerCase(),mobile=String(d.mobile||"").trim();
    const user=await env.DB.prepare("SELECT id,username,registered_email,registered_mobile FROM users WHERE username=? COLLATE NOCASE AND status='active'").bind(username).first();
    if(!user || !user.registered_email || !user.registered_mobile || user.registered_email.toLowerCase()!==email || user.registered_mobile!==mobile)
      return json({ok:true,message:"If the account and registered contact details match, verification codes will be sent."});
    const recent=await env.DB.prepare("SELECT COUNT(*) AS n FROM otp_challenges WHERE user_id=? AND purpose='password_reset' AND created_at>datetime('now','-15 minutes')").bind(user.id).first();
    if((recent?.n||0)>=10) return json({ok:true,message:"If the account and registered contact details match, verification codes will be sent."});
    try { const result=await createOtpPair(env,user,"password_reset"); await audit(env,null,"auth.password_reset_otp_requested","user",user.id,{channels:["email","sms"]},request); return json({ok:true,...result}); }
    catch(e) { return json({error:"OTP delivery is temporarily unavailable. Contact ILVORA support."},503); }
  }
  if(path==="/api/auth/otp/resend" && method==="POST") {
    const d=await bodyJson(request),group=String(d.challenge_id||"");
    const row=await env.DB.prepare("SELECT c.user_id,c.purpose,c.resend_after,u.registered_email,u.registered_mobile FROM otp_challenges c JOIN users u ON u.id=c.user_id WHERE c.challenge_group=? LIMIT 1").bind(group).first();
    if(!row || row.purpose!=="password_reset") return json({error:"Verification request is invalid or expired"},400);
    if(Date.parse(row.resend_after)>Date.now()) return json({error:"Please wait before requesting another OTP"},429);
    const user={id:row.user_id,registered_email:row.registered_email,registered_mobile:row.registered_mobile};
    try { const result=await createOtpPair(env,user,"password_reset",group); return json({ok:true,...result}); }
    catch(e) { return json({error:"OTP delivery is temporarily unavailable. Try again later."},503); }
  }
  if(path==="/api/auth/otp/reset-password" && method==="POST") {
    const d=await bodyJson(request),group=String(d.challenge_id||""),emailOtp=String(d.email_otp||""),smsOtp=String(d.mobile_otp||""),newPassword=String(d.new_password||"");
    if(!validPassword(newPassword)) return json({error:"New password must be 12+ characters with upper/lowercase and a number"},400);
    const rows=await env.DB.prepare("SELECT * FROM otp_challenges WHERE challenge_group=? AND purpose='password_reset' AND consumed_at IS NULL").bind(group).all();
    const emailRow=rows.results?.find(x=>x.channel==="email"),smsRow=rows.results?.find(x=>x.channel==="sms");
    if(!emailRow||!smsRow||Date.parse(emailRow.expires_at)<=Date.now()||Date.parse(smsRow.expires_at)<=Date.now()) return json({error:"OTP expired or invalid. Request a new OTP."},400);
    if(emailRow.attempts>=5||smsRow.attempts>=5) return json({error:"Too many incorrect OTP attempts. Request new codes."},429);
    const [emailHash,smsHash]=await Promise.all([otpDigest(env,group,emailOtp),otpDigest(env,group,smsOtp)]);
    if(emailHash!==emailRow.otp_hash||smsHash!==smsRow.otp_hash) {
      await env.DB.prepare("UPDATE otp_challenges SET attempts=attempts+1 WHERE challenge_group=?").bind(group).run();
      return json({error:"Email OTP or mobile OTP is incorrect"},400);
    }
    const hash=await makePasswordHash(newPassword);
    await env.DB.prepare("UPDATE users SET password_hash=?,must_change_password=0,updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(hash,emailRow.user_id).run();
    await env.DB.prepare("UPDATE otp_challenges SET consumed_at=CURRENT_TIMESTAMP WHERE challenge_group=?").bind(group).run();
    await env.DB.prepare("DELETE FROM sessions WHERE user_id=?").bind(emailRow.user_id).run();
    await audit(env,null,"auth.password_reset_completed","user",emailRow.user_id,{email_and_mobile_verified:true},request);
    return json({ok:true,message:"Password reset successfully. Sign in using your new password."});
  }

  if(path==="/api/auth/login" && method==="POST") {
    const data=await bodyJson(request);
    const username=String(data.username||"").trim();
    const password=String(data.password||"");
    const ip=request.headers.get("CF-Connecting-IP")||"unknown";
    const recent=await env.DB.prepare(`SELECT COUNT(*) AS n FROM login_attempts
      WHERE username_key=? AND ip_key=? AND attempted_at>datetime('now','-15 minutes') AND success=0`)
      .bind(username.toLowerCase(),ip).first();
    if((recent?.n||0)>=8) return json({error:"Too many failed attempts. Try again in 15 minutes."},429);
    const user=await env.DB.prepare("SELECT * FROM users WHERE username=? COLLATE NOCASE").bind(username).first();
    const ok=!!user && user.status==="active" && await verifyPassword(password,user.password_hash);
    await env.DB.prepare("INSERT INTO login_attempts(username_key,ip_key,success) VALUES(?,?,?)")
      .bind(username.toLowerCase(),ip,ok?1:0).run();
    if(!ok) {
      await audit(env,null,"auth.login_failed","user",user?.id||null,{username},request);
      return json({error:"Invalid username or password"},401);
    }
    const token=b64(crypto.getRandomValues(new Uint8Array(32)));
    const expires=new Date(Date.now()+SESSION_HOURS*3600000).toISOString();
    await env.DB.prepare("INSERT INTO sessions(id,user_id,token_hash,expires_at) VALUES(?,?,?,?)")
      .bind(crypto.randomUUID(),user.id,await sha256(token),expires).run();
    await audit(env,{...user},"auth.login","user",user.id,null,request);
    return json({ok:true,user:safeUser(user)},200,{"Set-Cookie":cookie(token,SESSION_HOURS*3600)});
  }

  if(path==="/api/auth/logout" && method==="POST") {
    const user=await currentUser(request,env);
    const raw=cookieValue(request,COOKIE);
    if(raw) await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?").bind(await sha256(raw)).run();
    if(user) await audit(env,user,"auth.logout","user",user.id,null,request);
    return json({ok:true},200,{"Set-Cookie":clearCookie()});
  }

  if(path==="/api/auth/me" && method==="GET") {
    const {user,error}=await requireUser(request,env); if(error) return error;
    return json({user:safeUser(user),attendance:await attendanceState(env,user)});
  }
  if(path==="/api/auth/attendance-status" && method==="GET") {
    const {user,error}=await requireUser(request,env); if(error) return error;
    return json({attendance:await attendanceState(env,user),user:safeUser(user)});
  }
  if(path==="/api/auth/attendance-checkin" && method==="POST") {
    const {user,error}=await requireUser(request,env); if(error) return error;
    if(["managing_director","administrator"].includes(user.role)) return json({ok:true,exempt:true});
    if(user.must_change_password) return json({error:"Change your temporary password before marking attendance"},403);
    const state=await attendanceState(env,user); if(state.marked) return json({ok:true,already_marked:true,attendance:state});
    const d=await bodyJson(request),lat=Number(d.latitude),lon=Number(d.longitude);
    if(!Number.isFinite(lat)||lat < -90||lat>90||!Number.isFinite(lon)||lon < -180||lon>180) return json({error:"Current GPS location is required to mark attendance"},400);
    const branchId=user.branch_id||"branch_kochi";
    const branch=await env.DB.prepare("SELECT id FROM branches WHERE id=? AND status='active'").bind(branchId).first();
    if(!branch) return json({error:"Your assigned branch is inactive. Contact ILVORA Administrator."},403);
    const fence=await env.DB.prepare("SELECT latitude,longitude,radius_m FROM branch_geofences WHERE branch_id=?").bind(branchId).first();
    let distance=null,verified=false;
    if(fence){const rad=x=>x*Math.PI/180,R=6371000,dLat=rad(lat-fence.latitude),dLon=rad(lon-fence.longitude),a=Math.sin(dLat/2)**2+Math.cos(rad(fence.latitude))*Math.cos(rad(lat))*Math.sin(dLon/2)**2;distance=Math.round(2*R*Math.asin(Math.sqrt(a)));if(distance>fence.radius_m)return json({error:`You are outside the authorised attendance area (${distance} m; limit ${fence.radius_m} m).`},403);verified=true;}
    const now=new Date(),date=indiaDateKey(now),id=crypto.randomUUID();
    const payload={attendance_date:date,check_in_at:now.toISOString(),check_in_local:now.toLocaleString("en-IN",{timeZone:"Asia/Kolkata"}),latitude:lat,longitude:lon,gps_distance_m:distance,gps_verified:verified,capture_method:"authenticated_gps_checkin",desk_access_granted:true};
    await env.DB.prepare(`INSERT INTO workforce_records(id,record_type,branch_id,owner_user_id,status,title,data_json,created_by,updated_by)
      VALUES(?,'attendance',?,?,'submitted',?,?,?,?)`).bind(id,branchId,user.id,`Attendance check-in ${date}`,JSON.stringify(payload),user.id,user.id).run();
    await audit(env,user,"attendance.checkin_completed","attendance",id,{attendance_date:date,branch_id:branchId,gps_verified:verified,gps_distance_m:distance},request);
    return json({ok:true,attendance:{required:true,marked:true,attendance_date:date,record_id:id,branch_id:branchId,gps_verified:verified,gps_distance_m:distance}} ,201);
  }

  const auth=await requireUser(request,env);
  if(auth.error) return auth.error;
  const actor=auth.user;
  if(actor.must_change_password && path!=="/api/auth/change-password")
    return json({error:"You must change your temporary password before using ILVORA Workforce"},403);
  if(!["managing_director","administrator"].includes(actor.role) && !["/api/auth/attendance-status","/api/auth/attendance-checkin","/api/auth/logout","/api/auth/change-password"].includes(path)) {
    const attendance=await attendanceState(env,actor);
    if(!attendance.marked) return json({error:"Attendance is required before accessing your ILVORA Workforce desk",attendance_required:true,attendance},428);
  }

  if(path==="/api/auth/change-password" && method==="POST") {
    const data=await bodyJson(request);
    if(!await verifyPassword(String(data.current_password||""),actor.password_hash))
      return json({error:"Current password is incorrect"},400);
    if(!validPassword(data.new_password)) return json({error:"New password must be 12+ characters with upper/lowercase and a number"},400);
    const hash=await makePasswordHash(data.new_password);
    await env.DB.prepare("UPDATE users SET password_hash=?,must_change_password=0,updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(hash,actor.id).run();
    await env.DB.prepare("DELETE FROM sessions WHERE user_id=? AND id<>?").bind(actor.id,actor.session_id).run();
    await audit(env,actor,"auth.password_changed","user",actor.id,null,request);
    return json({ok:true});
  }

  // Dedicated Administrator provisioning: MD only. This does not alter any existing role permissions.
  if(path==="/api/md/provision-administrator" && method==="POST") {
    if(actor.role!=="managing_director") return json({error:"Only the Managing Director may provision an Administrator account"},403);
    const data=await bodyJson(request);
    const username=String(data.username||"").trim();
    const displayName=String(data.display_name||"").trim();
    const email=String(data.registered_email||"").trim().toLowerCase(),mobile=String(data.registered_mobile||"").trim();
    if(!/^[A-Za-z0-9._-]{4,40}$/.test(username) || !displayName || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !/^\+[1-9]\d{7,14}$/.test(mobile))
      return json({error:"Provide username, full name, registered email and mobile in international format (+countrycode)"},400);
    const password=await generateInitialPassword(),id=crypto.randomUUID(),hash=await makePasswordHash(password);
    try { await env.DB.prepare(`INSERT INTO users(id,username,display_name,password_hash,role,branch_id,must_change_password,created_by,registered_email,registered_mobile) VALUES(?,?,?,?,'administrator',NULL,1,?,?,?)`).bind(id,username,displayName,hash,actor.id,email,mobile).run(); }
    catch { return json({error:"Username/email already exists or Administrator account could not be created"},409); }
    try { await sendEmail(env,email,"Your ILVORA Workforce initial login",`Hello ${displayName},\n\nYour ILVORA Workforce username is ${username}.\nYour automatically generated initial password is: ${password}\n\nThis password remains valid until you change it at first login. You must change it before accessing your desk. Keep it confidential.`); }
    catch { await env.DB.prepare("DELETE FROM users WHERE id=?").bind(id).run(); return json({error:"Account not created because initial credentials could not be delivered. Check email provider configuration."},503); }
    await audit(env,actor,"user.administrator_provisioned","user",id,{role:"administrator",branch_id:null,provisioned_by_md:true,credential_delivery:"email"},request);
    return json({ok:true,message:"Administrator account created. Initial password sent to registered email; change it at first login.",user:{id,username,display_name:displayName,role:"administrator",branch_id:null,must_change_password:true,credential_delivery:"sent"}},201);
  }

  if(path==="/api/users" && method==="GET") {
    if(!canManageUsers(actor.role)) return json({error:"Access denied"},403);
    let rows;
    if(actor.role==="branch_admin") {
      rows=await env.DB.prepare(`SELECT u.id,u.username,u.display_name,u.role,u.branch_id,u.status,u.created_at,b.name AS branch_name
        FROM users u LEFT JOIN branches b ON b.id=u.branch_id
        WHERE u.branch_id=? AND u.role IN ('employee','attendance_marker') AND lower(u.display_name) NOT LIKE '%demo employee%' AND lower(u.display_name) NOT LIKE '%sample employee%' AND lower(u.display_name) NOT LIKE '%illustrative employee%' ORDER BY u.display_name`)
        .bind(actor.branch_id).all();
    } else if(actor.role==="administrator") {
      rows=await env.DB.prepare(`SELECT u.id,u.username,u.display_name,u.role,u.branch_id,u.status,u.created_at,b.name AS branch_name
        FROM users u LEFT JOIN branches b ON b.id=u.branch_id
        WHERE u.role IN ('head_office_admin','branch_admin','employee','attendance_marker') AND lower(u.display_name) NOT LIKE '%demo employee%' AND lower(u.display_name) NOT LIKE '%sample employee%' AND lower(u.display_name) NOT LIKE '%illustrative employee%' ORDER BY u.display_name`).all();
    } else if(actor.role==="managing_director") {
      rows=await env.DB.prepare(`SELECT u.id,u.username,u.display_name,u.role,u.branch_id,u.status,u.created_at,b.name AS branch_name
        FROM users u LEFT JOIN branches b ON b.id=u.branch_id
        WHERE u.role <> 'managing_director' AND lower(u.display_name) NOT LIKE '%demo employee%' AND lower(u.display_name) NOT LIKE '%sample employee%' AND lower(u.display_name) NOT LIKE '%illustrative employee%' ORDER BY u.display_name`).all();
    } else {
      rows=await env.DB.prepare(`SELECT u.id,u.username,u.display_name,u.role,u.branch_id,u.status,u.created_at,b.name AS branch_name
        FROM users u LEFT JOIN branches b ON b.id=u.branch_id
        WHERE u.role IN ('branch_admin','employee','attendance_marker') AND lower(u.display_name) NOT LIKE '%demo employee%' AND lower(u.display_name) NOT LIKE '%sample employee%' AND lower(u.display_name) NOT LIKE '%illustrative employee%' ORDER BY u.display_name`).all();
    }
    return json({users:rows.results||[]});
  }

  // Account status changes are deliberately narrower than general user creation.
  // Only Administrator may suspend/reactivate/deactivate non-executive accounts.
  const accountStatusMatch=path.match(/^\/api\/users\/([A-Za-z0-9-]+)\/status$/);
  if(accountStatusMatch && method==="POST") {
    if(actor.role!=="administrator") return json({error:"Only Administrator may change account status"},403);
    const targetId=accountStatusMatch[1];
    const data=await bodyJson(request);
    const status=String(data.status||"");
    const reason=String(data.reason||"").trim();
    const reference=String(data.reference||"").trim();
    if(!["active","locked","inactive"].includes(status) || reason.length<8 || reference.length<4)
      return json({error:"Choose a valid status and provide an approval reference and reason"},400);
    const target=await env.DB.prepare("SELECT id,role,status,branch_id FROM users WHERE id=?").bind(targetId).first();
    if(!target) return json({error:"Account not found"},404);
    if(["managing_director","administrator"].includes(target.role)) return json({error:"Executive and Administrator accounts cannot be changed from this service"},403);
    if(target.id===actor.id) return json({error:"You cannot change your own account status"},403);
    await env.DB.prepare("UPDATE users SET status=?,updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(status,targetId).run();
    if(status!=="active") await env.DB.prepare("DELETE FROM sessions WHERE user_id=?").bind(targetId).run();
    await audit(env,actor,"user.account_status_changed","user",targetId,{from:target.status,to:status,reference,reason,sessions_revoked:status!=="active"},request);
    return json({ok:true,status,sessions_revoked:status!=="active"});
  }

  if(path==="/api/users" && method==="POST") {
    if(!canManageUsers(actor.role)) return json({error:"Access denied"},403);
    const data=await bodyJson(request);
    const role=String(data.role||"");
    if(!ROLES.has(role) || !canCreateRole(actor.role,role)) return json({error:"You are not authorised to create this role"},403);
    const username=String(data.username||"").trim(), displayName=String(data.display_name||"").trim();
    const email=String(data.registered_email||"").trim().toLowerCase(),mobile=String(data.registered_mobile||"").trim();
    if(!/^[A-Za-z0-9._-]{4,40}$/.test(username) || !displayName || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !/^\+[1-9]\d{7,14}$/.test(mobile))
      return json({error:"Provide username, full name, registered email and mobile in international format (+countrycode)"},400);
    let branchId=data.branch_id||null;
    if(["branch_admin","employee","attendance_marker"].includes(role) && !branchId)
      return json({error:"A branch must be assigned to this account"},400);
    if(actor.role==="branch_admin") branchId=actor.branch_id;
    if(["managing_director","administrator","head_office_admin"].includes(role)) branchId=null;
    if(branchId) {
      const branch=await env.DB.prepare("SELECT id FROM branches WHERE id=? AND status='active'").bind(branchId).first();
      if(!branch) return json({error:"Unknown or inactive branch"},400);
    }
    const password=await generateInitialPassword(),id=crypto.randomUUID(),hash=await makePasswordHash(password);
    try { await env.DB.prepare(`INSERT INTO users(id,username,display_name,password_hash,role,branch_id,must_change_password,created_by,registered_email,registered_mobile) VALUES(?,?,?,?,?,?,1,?,?,?)`).bind(id,username,displayName,hash,role,branchId,actor.id,email,mobile).run(); }
    catch { return json({error:"Username/email already exists or account could not be created"},409); }
    try { await sendEmail(env,email,"Your ILVORA Workforce initial login",`Hello ${displayName},\n\nYour ILVORA Workforce username is ${username}.\nYour automatically generated initial password is: ${password}\n\nThis password remains valid until you change it at first login. You must change it before accessing your desk. Keep it confidential.`); }
    catch { await env.DB.prepare("DELETE FROM users WHERE id=?").bind(id).run(); return json({error:"Account not created because initial credentials could not be delivered. Check email provider configuration."},503); }
    await audit(env,actor,"user.created","user",id,{role,branch_id:branchId,credential_delivery:"email"},request);
    return json({ok:true,user:{id,username,display_name:displayName,role,branch_id:branchId,must_change_password:true,credential_delivery:"sent"}},201);
  }

  if(path==="/api/branches" && method==="GET") {
    if(!["managing_director","administrator","head_office_admin"].includes(actor.role))
      return json({error:"Access denied"},403);
    const rows=await env.DB.prepare("SELECT id,code,name,city,status FROM branches WHERE status='active' ORDER BY name").all();
    return json({branches:rows.results||[]});
  }
  if(path==="/api/branches" && method==="POST") {
    if(!["managing_director","administrator"].includes(actor.role)) return json({error:"Only the Managing Director or Administrator may create a branch"},403);
    const d=await bodyJson(request),code=String(d.code||"").trim().toUpperCase(),name=String(d.name||"").trim(),city=String(d.city||"").trim();
    if(!/^[A-Z0-9-]{2,16}$/.test(code)||name.length<3||name.length>100||city.length<2||city.length>80) return json({error:"Enter a branch code, branch name and city"},400);
    const id="branch_"+crypto.randomUUID().replaceAll("-","").slice(0,16);
    try { await env.DB.prepare("INSERT INTO branches(id,code,name,city,status) VALUES(?,?,?,?,'active')").bind(id,code,name,city).run(); }
    catch { return json({error:"Branch code already exists or the branch could not be created"},409); }
    await audit(env,actor,"branch.created","branch",id,{code,name,city},request);
    return json({ok:true,branch:{id,code,name,city,status:"active"}},201);
  }

  if(path==="/api/audit" && method==="GET") {
    if(!["managing_director","administrator"].includes(actor.role)) return json({error:"Access denied"},403);
    const rows=await env.DB.prepare(`SELECT id,actor_user_id,actor_role,branch_id,action,target_type,target_id,details_json,created_at
      FROM audit_events ORDER BY created_at DESC LIMIT 200`).all();
    return json({events:rows.results||[]});
  }

  if(path==="/api/permissions" && method==="GET") {
    const rows=await env.DB.prepare("SELECT module_prefix FROM role_module_access WHERE role=? ORDER BY module_prefix").bind(actor.role).all();
    return json({role:actor.role,branch_id:actor.branch_id,modules:(rows.results||[]).map(x=>x.module_prefix)});
  }


  if(path==='/api/settings' && method==='GET') {
    if(!['managing_director','administrator'].includes(actor.role))return json({error:'Access denied'},403);
    const rows=await env.DB.prepare("SELECT setting_key,setting_value,updated_at FROM app_settings WHERE setting_key NOT IN ('bootstrap_completed','md_signatory_name') ORDER BY setting_key").all();return json({settings:rows.results||[],can_edit:actor.role==='administrator'});
  }
  if(path==='/api/settings' && method==='POST') {
    if(actor.role!=='administrator')return json({error:'Only Administrator may change operational system settings'},403);
    const d=await bodyJson(request),allowed={salary_cycle_days:[30],payslip_generation_day:[1,31],attendance_register_close_day:[1,31],paid_medical_leave_days_per_financial_year:[0,30],casual_leave_paid:[0,1],attendance_photo_retention_days:[1,30]};
    const key=String(d.key||''),value=String(d.value??'');if(!Object.prototype.hasOwnProperty.call(allowed,key))return json({error:'This setting cannot be changed here'},403);
    const n=Number(value);if(!Number.isFinite(n)||n<allowed[key][0]||n>allowed[key][1]||(key==='salary_cycle_days'&&n!==30))return json({error:'Invalid setting value'},400);
    await env.DB.prepare('UPDATE app_settings SET setting_value=?,updated_at=CURRENT_TIMESTAMP WHERE setting_key=?').bind(value,key).run();await audit(env,actor,'system.setting.updated','app_setting',key,{value},request);return json({ok:true,key,value});
  }

  if(path==='/api/dashboard/summary' && method==='GET') {
    let where='',args=[];
    if(actor.role==='employee'){where=' WHERE owner_user_id=?';args=[actor.id]}
    else if(actor.role==='branch_admin'){where=' WHERE branch_id=?';args=[actor.branch_id]}
    else if(actor.role==='attendance_marker') return json({role:actor.role,attendance_capture_only:true});
    const rows=await env.DB.prepare(`SELECT record_type,status,COUNT(*) AS total FROM workforce_records${where} GROUP BY record_type,status`).bind(...args).all();
    const byType={};for(const r of rows.results||[]){byType[r.record_type]??={};byType[r.record_type][r.status]=r.total}
    const pending=await env.DB.prepare(`SELECT COUNT(*) AS total FROM workforce_records${where}${where?' AND':' WHERE'} status IN ('draft','submitted','pending')`).bind(...args).first();
    return json({role:actor.role,branch_id:actor.branch_id,counts:byType,pending_approvals:pending?.total||0,generated_documents:actor.role==='employee'?0:(await env.DB.prepare('SELECT COUNT(*) AS total FROM generated_documents').first())?.total||0});
  }
  if(path==='/api/branches/geofence' && (method==='GET'||method==='POST')) {
    if(!['managing_director','administrator','head_office_admin'].includes(actor.role)) return json({error:'Access denied'},403);
    if(method==='GET'){const rows=await env.DB.prepare('SELECT g.*,b.name AS branch_name FROM branch_geofences g JOIN branches b ON b.id=g.branch_id ORDER BY b.name').all();return json({geofences:rows.results||[]})}
    const d=await bodyJson(request), branchId=String(d.branch_id||'');const lat=Number(d.latitude),lon=Number(d.longitude),radius=Number(d.radius_m||150);
    if(!await env.DB.prepare("SELECT id FROM branches WHERE id=? AND status='active'").bind(branchId).first())return json({error:'Active branch not found'},400);
    if(!Number.isFinite(lat)||lat < -90||lat>90||!Number.isFinite(lon)||lon < -180||lon>180||!Number.isInteger(radius)||radius<25||radius>2000)return json({error:'Enter valid coordinates and a radius between 25 and 2000 metres'},400);
    await env.DB.prepare(`INSERT INTO branch_geofences(branch_id,latitude,longitude,radius_m,updated_by) VALUES(?,?,?,?,?) ON CONFLICT(branch_id) DO UPDATE SET latitude=excluded.latitude,longitude=excluded.longitude,radius_m=excluded.radius_m,updated_by=excluded.updated_by,updated_at=CURRENT_TIMESTAMP`).bind(branchId,lat,lon,radius,actor.id).run();
    await audit(env,actor,'branch.geofence.updated','branch',branchId,{latitude:lat,longitude:lon,radius_m:radius},request);return json({ok:true});
  }
  if(path==='/api/notifications' && method==='GET') {
    if(!['managing_director','administrator','head_office_admin','branch_admin','employee'].includes(actor.role))return json({error:'Access denied'},403);
    let rows;
    if(actor.role==='employee') rows=await env.DB.prepare('SELECT * FROM notifications WHERE recipient_user_id=? OR recipient_branch_id=? ORDER BY created_at DESC LIMIT 200').bind(actor.id,actor.branch_id||'').all();
    else if(actor.role==='branch_admin') rows=await env.DB.prepare('SELECT * FROM notifications WHERE recipient_branch_id=? OR recipient_user_id IN (SELECT id FROM users WHERE branch_id=?) ORDER BY created_at DESC LIMIT 200').bind(actor.branch_id,actor.branch_id).all();
    else rows=await env.DB.prepare('SELECT * FROM notifications ORDER BY created_at DESC LIMIT 500').all();
    return json({notifications:rows.results||[]});
  }
  if(path==='/api/notifications' && method==='POST') {
    if(!['managing_director','administrator','head_office_admin','branch_admin'].includes(actor.role))return json({error:'Access denied'},403);
    const d=await bodyJson(request),title=String(d.title||'').trim(),body=String(d.body||'').trim();if(!title||!body)return json({error:'Title and message are required'},400);
    let branchId=d.branch_id||null,userId=d.recipient_user_id||null;
    if(actor.role==='branch_admin'){branchId=actor.branch_id;if(userId){const u=await env.DB.prepare('SELECT id FROM users WHERE id=? AND branch_id=?').bind(userId,actor.branch_id).first();if(!u)return json({error:'Recipient is outside your branch'},403)}}
    if(!branchId&&!userId)return json({error:'Choose a branch or an employee recipient'},400);
    const id=crypto.randomUUID();await env.DB.prepare('INSERT INTO notifications(id,recipient_user_id,recipient_branch_id,title,body,category,created_by) VALUES(?,?,?,?,?,?,?)').bind(id,userId,branchId,title,body,String(d.category||'announcement'),actor.id).run();await audit(env,actor,'notification.created','notification',id,{branch_id:branchId,recipient_user_id:userId},request);return json({ok:true,id},201);
  }
  const notificationMatch=path.match(/^\/api\/notifications\/([A-Za-z0-9_-]+)\/read$/);
  if(notificationMatch&&method==='POST') {if(!['managing_director','administrator','head_office_admin','branch_admin','employee'].includes(actor.role))return json({error:'Access denied'},403);const r=await env.DB.prepare('SELECT * FROM notifications WHERE id=?').bind(notificationMatch[1]).first();if(!r)return json({error:'Notification not found'},404);if(r.recipient_user_id&&r.recipient_user_id!==actor.id)return json({error:'Not your notification'},403);if(r.recipient_branch_id&&r.recipient_branch_id!==actor.branch_id&&!['managing_director','administrator','head_office_admin'].includes(actor.role))return json({error:'Branch scope violation'},403);await env.DB.prepare('UPDATE notifications SET read_at=CURRENT_TIMESTAMP WHERE id=?').bind(r.id).run();return json({ok:true});}

  if(path==='/api/payroll/run' && method==='POST') {
    if(!['managing_director','administrator'].includes(actor.role)) return json({error:'Only Administrator or Managing Director may run payroll'},403);
    const data=await bodyJson(request), month=String(data.payroll_month||'');
    if(!/^\d{4}-\d{2}$/.test(month) || Number(month.slice(5))<1 || Number(month.slice(5))>12) return json({error:'Payroll month must be YYYY-MM'},400);
    const branchId=data.branch_id||null;
    if(branchId && !await env.DB.prepare("SELECT id FROM branches WHERE id=? AND status='active'").bind(branchId).first()) return json({error:'Invalid branch'},400);
    const employees=await env.DB.prepare(`SELECT id,username,display_name,branch_id FROM users WHERE role='employee' AND status='active' ${branchId?'AND branch_id=?':''} ORDER BY username`).bind(...(branchId?[branchId]:[])).all();
    const settingRows=await env.DB.prepare("SELECT setting_key,setting_value FROM app_settings WHERE setting_key IN ('salary_cycle_days','paid_medical_leave_days_per_financial_year')").all();const settings=Object.fromEntries((settingRows.results||[]).map(x=>[x.setting_key,Number(x.setting_value)]));const daysInCycle=settings.salary_cycle_days||30,paidMedicalQuota=settings.paid_medical_leave_days_per_financial_year??5,start=`${month}-01`, end=`${month}-31`, created=[] , skipped=[];
    for(const emp of employees.results||[]) {
      const exists=await env.DB.prepare("SELECT id FROM workforce_records WHERE record_type='payroll' AND owner_user_id=? AND json_extract(data_json,'$.payroll_month')=? LIMIT 1").bind(emp.id,month).first();
      if(exists){skipped.push({username:emp.username,reason:'Payroll already exists for this month'});continue}
      const salaryRow=await env.DB.prepare("SELECT data_json FROM workforce_records WHERE record_type='salary' AND owner_user_id=? AND status='approved' ORDER BY updated_at DESC LIMIT 1").bind(emp.id).first();
      if(!salaryRow){skipped.push({username:emp.username,reason:'No approved salary structure'});continue}
      const salary=JSON.parse(salaryRow.data_json||'{}'), monthlySalary=Number(salary.monthly_salary||0);
      if(monthlySalary<=0){skipped.push({username:emp.username,reason:'Approved salary structure has no valid monthly_salary'});continue}
      const rosterRows=await env.DB.prepare("SELECT data_json FROM workforce_records WHERE record_type='rosters' AND owner_user_id=? AND status='approved'").bind(emp.id).all();
      const scheduledDates=new Set((rosterRows.results||[]).map(r=>JSON.parse(r.data_json||'{}').duty_date).filter(d=>typeof d==='string'&&d.startsWith(month)));
      const scheduledDays=Math.min(daysInCycle,scheduledDates.size);
      if(!scheduledDays){skipped.push({username:emp.username,reason:'No approved duty roster for this month'});continue}
      const attendanceRows=await env.DB.prepare("SELECT data_json FROM workforce_records WHERE record_type='attendance' AND owner_user_id=? AND status='approved'").bind(emp.id).all();
      const attendedDates=new Set((attendanceRows.results||[]).map(r=>JSON.parse(r.data_json||'{}').attendance_date).filter(d=>typeof d==='string'&&d.startsWith(month)&&scheduledDates.has(d)));
      const fyStart=Number(month.slice(5))>=4?`${month.slice(0,4)}-04-01`:`${Number(month.slice(0,4))-1}-04-01`;
      const fyEnd=Number(month.slice(5))>=4?`${Number(month.slice(0,4))+1}-03-31`:`${month.slice(0,4)}-03-31`;
      const leaveRows=await env.DB.prepare("SELECT data_json FROM workforce_records WHERE record_type='leaves' AND owner_user_id=? AND status='approved'").bind(emp.id).all();
      let priorMedical=0, monthMedical=0;
      for(const r of leaveRows.results||[]){const l=JSON.parse(r.data_json||'{}');if(!String(l.start_date||'').match(/^\d{4}-\d{2}-\d{2}$/)||!String(l.end_date||'').match(/^\d{4}-\d{2}-\d{2}$/))continue;const a=new Date(l.start_date+'T00:00:00Z'),b=new Date(l.end_date+'T00:00:00Z');if(b<a)continue;const days=Math.floor((b-a)/86400000)+1;const med=/medical/i.test(String(l.leave_type||''));if(!med)continue;const overlapStart=l.start_date>fyStart?l.start_date:fyStart, overlapEnd=l.end_date<fyEnd?l.end_date:fyEnd;if(overlapEnd<overlapStart)continue;const fyDays=Math.floor((new Date(overlapEnd+'T00:00:00Z')-new Date(overlapStart+'T00:00:00Z'))/86400000)+1;const priorEnd=l.end_date<start?l.end_date:(new Date(start+'T00:00:00Z').getTime()-86400000);const priorStart=l.start_date>fyStart?l.start_date:fyStart;if(priorEnd>=priorStart)priorMedical+=Math.floor((new Date(priorEnd+'T00:00:00Z')-new Date(priorStart+'T00:00:00Z'))/86400000)+1;const curStart=l.start_date>start?l.start_date:start,curEnd=l.end_date<end?l.end_date:end;if(curEnd>=curStart)monthMedical+=Math.floor((new Date(curEnd+'T00:00:00Z')-new Date(curStart+'T00:00:00Z'))/86400000)+1;}
      const paidMedical=Math.max(0,Math.min(monthMedical,paidMedicalQuota-priorMedical));
      const payableDays=Math.min(scheduledDays,attendedDates.size+paidMedical);
      const basic=Number(salary.basic||monthlySalary), allowances=Number(salary.allowances||0), standardDeductions=Number(salary.deductions||salary.standard_deductions||0);
      const gross=Number(monthlySalary.toFixed(2));
      const unpaidDays=Math.max(0,scheduledDays-payableDays), unpaidDeduction=Number((monthlySalary/daysInCycle*unpaidDays).toFixed(2));
      const deductions=Number((standardDeductions+unpaidDeduction).toFixed(2)), net=Number((gross-deductions).toFixed(2));
      const payrollData={payroll_month:month,employee_username:emp.username,employee_name:emp.display_name,monthly_salary:monthlySalary,scheduled_days:scheduledDays,attendance_days:attendedDates.size,paid_medical_leave_days:paidMedical,unpaid_days:unpaidDays,payable_days:payableDays,basic,allowances,gross,deductions,unpaid_deduction:unpaidDeduction,net,currency:'INR',salary_cycle_days:daysInCycle};
      const id=crypto.randomUUID();
      await env.DB.prepare(`INSERT INTO workforce_records(id,record_type,branch_id,owner_user_id,status,title,data_json,created_by,updated_by) VALUES(?, 'payroll', ?, ?, 'draft', ?, ?, ?, ?)`)
        .bind(id,emp.branch_id,emp.id,`Payroll ${month} – ${emp.username}`,JSON.stringify(payrollData),actor.id,actor.id).run();
      created.push({id,username:emp.username,gross,deductions,net,payable_days:payableDays});
    }
    await audit(env,actor,'payroll.run_created','payroll',month,{created:created.length,skipped:skipped.length,branch_id:branchId},request);
    return json({ok:true,payroll_month:month,created,skipped,totals:{employees:created.length,gross:created.reduce((a,x)=>a+x.gross,0),deductions:created.reduce((a,x)=>a+x.deductions,0),net:created.reduce((a,x)=>a+x.net,0)}},201);
  }

  // Operational record workspace. All access is enforced here, not by browser UI.
  const typePolicy = {
    employees:{read:['managing_director','administrator','head_office_admin','branch_admin','employee'],write:['managing_director','administrator','head_office_admin','branch_admin','employee']},
    onboarding:{read:['managing_director','administrator','head_office_admin','branch_admin'],write:['managing_director','administrator','head_office_admin','branch_admin']},
    attendance:{read:['managing_director','administrator','head_office_admin','branch_admin','employee'],write:['managing_director','administrator','head_office_admin','branch_admin','attendance_marker']},
    rosters:{read:['managing_director','administrator','head_office_admin','branch_admin'],write:['managing_director','administrator','head_office_admin','branch_admin']},
    leaves:{read:['managing_director','administrator','head_office_admin','branch_admin','employee'],write:['managing_director','administrator','head_office_admin','branch_admin','employee']},
    salary:{read:['managing_director','administrator'],write:['managing_director','administrator']},
    payroll:{read:['managing_director','administrator'],write:['managing_director','administrator']},
    payslips:{read:['managing_director','administrator','employee'],write:['managing_director','administrator']},
    documents:{read:['managing_director','administrator','head_office_admin','branch_admin','employee'],write:['managing_director','administrator','head_office_admin','branch_admin']},
    notices:{read:['managing_director','administrator','head_office_admin','branch_admin','employee'],write:['managing_director','administrator','head_office_admin','branch_admin']},
    complaints:{read:['managing_director','administrator','head_office_admin','branch_admin','employee'],write:['managing_director','administrator','head_office_admin','branch_admin','employee']},
    helpdesk:{read:['managing_director','administrator','head_office_admin','branch_admin','employee'],write:['managing_director','administrator','head_office_admin','branch_admin','employee']},
    advances:{read:['managing_director','administrator','head_office_admin','branch_admin','employee'],write:['managing_director','administrator','head_office_admin','branch_admin']},
    resignations:{read:['managing_director','administrator','head_office_admin','branch_admin','employee'],write:['managing_director','administrator','head_office_admin','branch_admin','employee']},
    contracts:{read:['managing_director','administrator','head_office_admin'],write:['managing_director','administrator']},
    expenses:{read:['managing_director','administrator'],write:['managing_director','administrator']},
    inventory:{read:['managing_director','administrator'],write:['managing_director','administrator']},
    compliance:{read:['managing_director','administrator','head_office_admin'],write:['managing_director','administrator','head_office_admin']},
    licenses:{read:['managing_director','administrator'],write:['managing_director','administrator']},
    tasks:{read:['managing_director','administrator','head_office_admin','branch_admin','employee'],write:['managing_director','administrator','head_office_admin','branch_admin']},
    decisions:{read:['managing_director'],write:['managing_director']},
    branch_settings:{read:['managing_director','administrator','head_office_admin'],write:['managing_director','administrator','head_office_admin']},
    settings:{read:['managing_director','administrator'],write:['managing_director','administrator']},
    reports:{read:['managing_director','administrator','head_office_admin','branch_admin'],write:['managing_director','administrator']},
    notifications:{read:['managing_director','administrator','head_office_admin','branch_admin','employee'],write:['managing_director','administrator','head_office_admin','branch_admin'] }
  };
  const workspaceMatch=path.match(/^\/api\/workspace\/([a-z_]+)(?:\/([A-Za-z0-9_-]+))?$/);
  if(workspaceMatch) {
    const type=workspaceMatch[1], recordId=workspaceMatch[2]||null, policy=typePolicy[type];
    if(!policy) return json({error:'Unknown workspace module'},404);
    if(method==='GET' && !policy.read.includes(actor.role)) return json({error:'Access denied'},403);
    if(method!=='GET' && !policy.write.includes(actor.role)) return json({error:'Access denied'},403);
    const branchScope=['branch_admin','employee','attendance_marker'].includes(actor.role);
    if(method==='GET') {
      let sql='SELECT * FROM workforce_records WHERE record_type=?', args=[type];
      if(actor.role==='employee' && type==='notices') { sql+=' AND (branch_id IS NULL OR branch_id=?)'; args.push(actor.branch_id); }
      else if(actor.role==='employee') { sql+=' AND (owner_user_id=? OR created_by=?)'; args.push(actor.id,actor.id); }
      else if(branchScope) { sql+=' AND branch_id=?'; args.push(actor.branch_id); }
      if(recordId) { sql+=' AND id=?'; args.push(recordId); }
      sql+=' ORDER BY updated_at DESC LIMIT 500';
      const rows=await env.DB.prepare(sql).bind(...args).all();
      return json({records:(rows.results||[]).map(r=>({...r,data:JSON.parse(r.data_json||'{}'),data_json:undefined}))});
    }
    if(method==='POST') {
      const data=await bodyJson(request);
      const title=String(data.title||'').trim();
      if(!title || title.length>180) return json({error:'A title (maximum 180 characters) is required'},400);
      let branchId=data.branch_id||actor.branch_id||null;
      if(actor.role==='branch_admin'||actor.role==='employee'||actor.role==='attendance_marker') branchId=actor.branch_id;
      if(branchId) { const b=await env.DB.prepare("SELECT id FROM branches WHERE id=? AND status='active'").bind(branchId).first(); if(!b) return json({error:'Invalid branch'},400); }
      let ownerId=data.owner_user_id|| (actor.role==='employee'?actor.id:null);
      if(data.owner_username && actor.role!=='employee') { const target=await env.DB.prepare("SELECT id,branch_id FROM users WHERE username=? COLLATE NOCASE AND role='employee' AND status='active'").bind(String(data.owner_username).trim()).first(); if(!target) return json({error:'Active employee username not found'},400); ownerId=target.id; if(!branchId) branchId=target.branch_id; }
      if(actor.role==='employee') ownerId=actor.id;
      if(ownerId) {
        const owner=await env.DB.prepare('SELECT id,branch_id FROM users WHERE id=? AND status=\'active\'').bind(ownerId).first();
        if(!owner) return json({error:'Employee account not found'},400);
        if(branchId && owner.branch_id!==branchId) return json({error:'Employee does not belong to selected branch'},403);
      }
      const payload=data.data&&typeof data.data==='object'?data.data:{};
      if(JSON.stringify(payload).length>200000) return json({error:'Record details exceed the 200 KB limit'},413);
      if(type==='attendance') {
        if(!branchId) return json({error:'Attendance records must be assigned to a branch'},400);
        const fence=await env.DB.prepare('SELECT latitude,longitude,radius_m FROM branch_geofences WHERE branch_id=?').bind(branchId||'').first();
        if(fence){const lat=Number(payload.latitude),lon=Number(payload.longitude);if(!Number.isFinite(lat)||!Number.isFinite(lon))return json({error:'GPS coordinates are required for this branch attendance capture'},400);const rad=x=>x*Math.PI/180,R=6371000,dLat=rad(lat-fence.latitude),dLon=rad(lon-fence.longitude),a=Math.sin(dLat/2)**2+Math.cos(rad(fence.latitude))*Math.cos(rad(lat))*Math.sin(dLon/2)**2,dist=2*R*Math.asin(Math.sqrt(a));if(dist>fence.radius_m)return json({error:'Attendance capture is outside the approved branch geofence'},403);payload.gps_distance_m=Math.round(dist);payload.gps_verified=true;}
      }
      if(type==='attendance' && ownerId && payload.attendance_date) {
        const dup=await env.DB.prepare("SELECT id FROM workforce_records WHERE record_type='attendance' AND owner_user_id=? AND json_extract(data_json,'$.attendance_date')=? AND status<>'cancelled' LIMIT 1").bind(ownerId,String(payload.attendance_date)).first();
        if(dup) return json({error:'Attendance has already been recorded for this employee and date'},409);
      }
      if(type==='leaves' && ownerId && payload.start_date && payload.end_date) {
        const overlap=await env.DB.prepare("SELECT id FROM workforce_records WHERE record_type='leaves' AND owner_user_id=? AND status IN ('submitted','pending','approved') AND json_extract(data_json,'$.start_date')<=? AND json_extract(data_json,'$.end_date')>=? LIMIT 1").bind(ownerId,String(payload.end_date),String(payload.start_date)).first();
        if(overlap) return json({error:'This employee already has a pending or approved leave overlapping those dates'},409);
      }
      if(type==='advances' && Number(payload.monthly_salary)>0 && Number(payload.amount)>=0) payload.percent_of_monthly_salary=Number((Number(payload.amount)/Number(payload.monthly_salary)*100).toFixed(2));
      if(type==='rosters' && ownerId && payload.duty_date && payload.start_time && payload.end_time) {
        const conflict=await env.DB.prepare("SELECT id,data_json FROM workforce_records WHERE record_type='rosters' AND owner_user_id=? AND json_extract(data_json,'$.duty_date')=? AND status<>'cancelled'").bind(ownerId,String(payload.duty_date)).all();
        const toMin=t=>{const m=String(t).match(/^(\d{1,2}):(\d{2})$/);return m?Number(m[1])*60+Number(m[2]):null};
        const a=toMin(payload.start_time), b=toMin(payload.end_time); if(a===null||b===null||a===b) return json({error:'Roster start and end times must be valid and different'},400);
        for(const row of conflict.results||[]){const d=JSON.parse(row.data_json||'{}'),c=toMin(d.start_time),e=toMin(d.end_time);if(c!==null&&e!==null&&Math.max(a,c)<Math.min(b,e))return json({error:'Duty roster overlaps an existing shift for this employee'},409)}
      }
      const id=crypto.randomUUID(), status=String(data.status||'draft');
      if(!['draft','submitted','pending','reviewed','approved','rejected','returned','paid','archived','cancelled'].includes(status)) return json({error:'Invalid record status'},400);
      await env.DB.prepare(`INSERT INTO workforce_records(id,record_type,branch_id,owner_user_id,status,title,data_json,created_by,updated_by)
        VALUES(?,?,?,?,?,?,?,?,?)`).bind(id,type,branchId,ownerId,status,title,JSON.stringify(payload),actor.id,actor.id).run();
      await audit(env,actor,`${type}.created`,type,id,{status},request);
      return json({ok:true,id,record:{id,record_type:type,branch_id:branchId,owner_user_id:ownerId,status,title,data:payload}},201);
    }
    if((method==='PATCH'||method==='PUT') && recordId) {
      const old=await env.DB.prepare('SELECT * FROM workforce_records WHERE id=? AND record_type=?').bind(recordId,type).first();
      if(!old) return json({error:'Record not found'},404);
      if(actor.role==='branch_admin' && old.branch_id!==actor.branch_id) return json({error:'Branch scope violation'},403);
      if(actor.role==='employee' && old.owner_user_id!==actor.id) return json({error:'Own-record access only'},403);
      if(actor.role==='attendance_marker') return json({error:'Attendance Marker accounts may create capture records but cannot edit existing attendance'},403);
      const data=await bodyJson(request);
      let nextStatus=data.status===undefined?old.status:String(data.status);
      if(['approved','rejected','returned'].includes(data.status)) {
        const approvalRoles={employees:['managing_director','administrator','head_office_admin','branch_admin'],onboarding:['managing_director','administrator','head_office_admin','branch_admin'],rosters:['managing_director','administrator','head_office_admin','branch_admin'],payslips:['managing_director','administrator'],payroll:['managing_director','administrator'],contracts:['managing_director','administrator'],experience:['managing_director','administrator'],documents:['managing_director','administrator','head_office_admin'],notices:['managing_director','administrator','head_office_admin','branch_admin'],complaints:['managing_director','administrator','head_office_admin','branch_admin'],helpdesk:['managing_director','administrator','head_office_admin','branch_admin'],compliance:['managing_director','administrator','head_office_admin'],licenses:['managing_director','administrator'],expenses:['managing_director','administrator'],inventory:['managing_director','administrator']};
        if(approvalRoles[type] && !approvalRoles[type].includes(actor.role)) return json({error:'Your role cannot approve, reject or return this record'},403);
      }
      if(type==='attendance' && ['approved','rejected','returned'].includes(data.status) && actor.role!=='head_office_admin') return json({error:'Attendance correction approval is reserved for Head Office Admin'},403);
      if(type==='resignations' && ['approved','rejected'].includes(data.status) && actor.role!=='managing_director') return json({error:'Final resignation approval is reserved for the Managing Director'},403);
      if(type==='leaves' && data.status==='approved' && !['branch_admin','head_office_admin'].includes(actor.role)) return json({error:'Leave approval is restricted to Branch Admin (up to 5 days) and Head Office Admin (over 5 days)'},403);
      if(type==='leaves' && data.status==='approved' && actor.role==='head_office_admin') { const d=data.data||JSON.parse(old.data_json||'{}'); if(Number(d.days||0)<=5) return json({error:'Head Office Admin approval is reserved for leave requests over 5 days'},403); }
      if(type==='leaves' && ['approved','rejected','returned'].includes(data.status)) {
        const d=data.data||JSON.parse(old.data_json||'{}');
        const start=Date.parse(String(d.start_date||'')), end=Date.parse(String(d.end_date||''));
        if(!Number.isFinite(start)||!Number.isFinite(end)||end<start) return json({error:'Valid leave start and end dates are required before approval'},400);
        const leaveDays=Math.floor((end-start)/86400000)+1;
        if(actor.role==='branch_admin' && leaveDays>5) return json({error:'Branch Admin approval is limited to leave requests of up to 5 calendar days'},403);
        if(actor.role==='head_office_admin' && leaveDays<=5) return json({error:'Head Office Admin approval is reserved for leave requests over 5 calendar days'},403);
      }
      if(type==='advances' && ['approved','rejected','returned'].includes(data.status) && !['administrator','managing_director'].includes(actor.role)) return json({error:'Advance approval is restricted to Administrator and Managing Director'},403);
      if(type==='advances' && ['approved','rejected','returned'].includes(data.status)) {
        const d=data.data||JSON.parse(old.data_json||'{}');
        if(!old.owner_user_id) return json({error:'Advance must be linked to an employee'},400);
        const salaryRow=await env.DB.prepare("SELECT data_json FROM workforce_records WHERE record_type='salary' AND owner_user_id=? AND status='approved' ORDER BY updated_at DESC LIMIT 1").bind(old.owner_user_id).first();
        if(!salaryRow) return json({error:'An approved salary structure is required before approving an employee advance'},409);
        const salaryData=JSON.parse(salaryRow.data_json||'{}'), monthlySalary=Number(salaryData.monthly_salary||0), amount=Number(d.amount||0);
        if(monthlySalary<=0||amount<=0) return json({error:'Valid approved monthly salary and advance amount are required'},400);
        const pct=amount/monthlySalary*100;
        if(actor.role==='administrator' && pct>25) return json({error:'Advances above 25% of approved monthly salary require Managing Director approval'},403);
      }
      const nextTitle=data.title===undefined?old.title:String(data.title).trim();
      const oldPayload=JSON.parse(old.data_json||'{}');const nextPayload=data.data===undefined?oldPayload:{...oldPayload,...data.data};
      if(['approved','rejected','returned'].includes(nextStatus)&&String(nextPayload.decision_note||'').trim().length<4)return json({error:'A decision note is required for approval, rejection or return'},400);
      if(!['draft','submitted','pending','reviewed','approved','rejected','returned','paid','archived','cancelled'].includes(nextStatus)) return json({error:'Invalid record status'},400);
      if(JSON.stringify(nextPayload).length>200000) return json({error:'Record details exceed the 200 KB limit'},413);
      const approvedBy=(old.status!=='approved' && nextStatus==='approved')?actor.id:old.approved_by;
      await env.DB.prepare(`UPDATE workforce_records SET title=?,status=?,data_json=?,updated_by=?,approved_by=?,updated_at=CURRENT_TIMESTAMP WHERE id=?`)
        .bind(nextTitle,nextStatus,JSON.stringify(nextPayload),actor.id,approvedBy||null,recordId).run();
      await audit(env,actor,`${type}.updated`,type,recordId,{from:old.status,to:nextStatus,decision_note:nextPayload.decision_note||null},request);
      return json({ok:true,id:recordId,status:nextStatus});
    }
    return json({error:'Method not allowed'},405);
  }

  // MD-only company signatory asset management. Historical documents embed immutable snapshots.
  if(path==='/api/md/signatory' && (method==='GET'||method==='POST')) {
    if(actor.role!=='managing_director') return json({error:'Managing Director access only'},403);
    if(method==='GET') {
      const rows=await env.DB.prepare('SELECT asset_key,mime_type,display_name,version,uploaded_at FROM document_assets ORDER BY asset_key').all();
      const name=await env.DB.prepare("SELECT setting_value FROM app_settings WHERE setting_key='md_signatory_name'").first();
      return json({assets:rows.results||[],md_name:name?.setting_value||''});
    }
    const data=await bodyJson(request), key=String(data.asset_key||'');
    if(data.action==='save_name') { const name=String(data.display_name||'').trim(); if(!name||name.length>120) return json({error:'Enter the full Managing Director name'},400); await env.DB.prepare("INSERT INTO app_settings(setting_key,setting_value) VALUES('md_signatory_name',?) ON CONFLICT(setting_key) DO UPDATE SET setting_value=excluded.setting_value,updated_at=CURRENT_TIMESTAMP").bind(name).run(); await audit(env,actor,'md.signatory_name.updated','app_setting','md_signatory_name',null,request); return json({ok:true}); }
    if(!['md_signature','company_seal','company_logo'].includes(key)) return json({error:'Invalid asset key'},400);
    const mime=String(data.mime_type||''); const urlData=String(data.data_url||'');
    if(!['image/png','image/jpeg','image/webp'].includes(mime) || !urlData.startsWith(`data:${mime};base64,`) || urlData.length>420000)
      return json({error:'Upload a PNG, JPEG or WebP image up to approximately 300 KB'},400);
    const displayName=String(data.display_name||'').trim().slice(0,120);
    await env.DB.prepare(`INSERT INTO document_assets(asset_key,mime_type,data_url,display_name,version,uploaded_by)
      VALUES(?,?,?,?,1,?) ON CONFLICT(asset_key) DO UPDATE SET mime_type=excluded.mime_type,data_url=excluded.data_url,
      display_name=excluded.display_name,version=document_assets.version+1,uploaded_by=excluded.uploaded_by,uploaded_at=CURRENT_TIMESTAMP`)
      .bind(key,mime,urlData,displayName,actor.id).run();
    await audit(env,actor,'md.signatory_asset.updated','document_asset',key,{display_name:displayName},request);
    return json({ok:true,message:'Asset saved for future documents. Existing documents retain their original snapshot.'});
  }

  if(path==='/api/documents/generate' && method==='POST') {
    if(!['managing_director','administrator','head_office_admin','branch_admin'].includes(actor.role)) return json({error:'Access denied'},403);
    const data=await bodyJson(request);
    const allowedTypes=['payslip','employment_contract','onboarding_confirmation','experience_letter','leave_approval'];
    const type=String(data.document_type||''); if(!allowedTypes.includes(type)) return json({error:'Unsupported document type'},400);
    if(type==='payslip' && !['managing_director','administrator'].includes(actor.role)) return json({error:'Payroll authorisation required'},403);
    if(type==='employment_contract' && !['managing_director','administrator'].includes(actor.role)) return json({error:'Contract authorisation required'},403);
    const sourceType={payslip:'payroll',employment_contract:'contracts',onboarding_confirmation:'onboarding',experience_letter:'resignations',leave_approval:'leaves'}[type];
    if(!data.record_id) return json({error:'An approved source record ID is required before an official document can be generated'},400);
    const source=await env.DB.prepare('SELECT id,branch_id,owner_user_id,status,data_json,approved_by FROM workforce_records WHERE id=? AND record_type=?').bind(String(data.record_id),sourceType).first();
    if(!source || source.status!=='approved') return json({error:'The linked source record must exist and be approved before document generation'},409);
    if(type==='experience_letter' && JSON.parse(source.data_json||'{}').clearance_complete!==true) return json({error:'Experience letters require completed exit clearance'},409);
    const employeeRef=String(data.employee_user_id||data.employee_username||'').trim();
    const employee=await env.DB.prepare("SELECT id,display_name,username,branch_id FROM users WHERE (id=? OR username=? COLLATE NOCASE) AND status='active'").bind(employeeRef,employeeRef).first();
    if(!employee) return json({error:'Active employee account is required'},400);
    if(actor.role==='branch_admin' && employee.branch_id!==actor.branch_id) return json({error:'Branch scope violation'},403);
    if(source.owner_user_id && source.owner_user_id!==employee.id) return json({error:'Document employee does not match approved source record'},403);
    if(source.branch_id && source.branch_id!==employee.branch_id) return json({error:'Document employee branch does not match source record'},403);
    const assets=await env.DB.prepare('SELECT asset_key,mime_type,data_url,display_name,version FROM document_assets').all();
    const mdNameRow=await env.DB.prepare("SELECT setting_value FROM app_settings WHERE setting_key='md_signatory_name'").first();
    const byKey=Object.fromEntries((assets.results||[]).map(a=>[a.asset_key,a]));
    const payload={...(data.data&&typeof data.data==='object'?data.data:{}),...JSON.parse(source.data_json||'{}')};
    const logo=byKey.company_logo?.data_url||'/assets/ilvora-healthcare-logo.png';
    const signature=byKey.md_signature?.data_url||''; const seal=byKey.company_seal?.data_url||'';
    const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
    const labels={payslip:'Salary Payslip',employment_contract:'Employment Contract',onboarding_confirmation:'Onboarding Confirmation Letter',experience_letter:'Experience Letter',leave_approval:'Leave Approval Letter'};
    const docNo=`ILV-${new Date().getFullYear()}-${crypto.randomUUID().slice(0,8).toUpperCase()}`;
    const details=Object.entries(payload).map(([k,v])=>`<tr><th>${esc(k.replace(/_/g,' '))}</th><td>${esc(v)}</td></tr>`).join('');
    const signatureBlock=`<section class="sign"><div>${signature?`<img class="sig" src="${signature}" alt="Managing Director signature">`:'<div class="pending">Signature image pending upload</div>'}<b>${esc(mdNameRow?.setting_value||byKey.md_signature?.display_name||'Managing Director')}</b><br>Managing Director</div>${seal?`<img class="seal" src="${seal}" alt="Company seal">`:'<div class="pending">Company seal pending upload</div>'}</section>`;
    const html=`<!doctype html><html><head><meta charset="utf-8"><title>${esc(labels[type])} ${esc(docNo)}</title><style>body{font:14px Arial;color:#203447;margin:34px}header{display:flex;align-items:center;justify-content:space-between;border-bottom:3px solid #c8a45d;padding-bottom:16px}header img{max-width:210px;max-height:75px;object-fit:contain}h1{color:#10243a;font-size:22px}table{width:100%;border-collapse:collapse;margin-top:22px}th,td{text-align:left;padding:10px;border:1px solid #dce4e9;text-transform:capitalize}th{width:32%;background:#f2f5f7}.sign{display:flex;align-items:end;justify-content:space-between;margin-top:60px;gap:20px}.sig{display:block;max-width:180px;max-height:75px;object-fit:contain}.seal{max-width:115px;max-height:115px;object-fit:contain}.pending{margin-top:45px;color:#875f14;background:#fff8e8;padding:12px}.foot{margin-top:35px;border-top:1px solid #ddd;padding-top:10px;color:#637787;font-size:11px}@media print{body{margin:15mm}}</style></head><body><header><img src="${logo}" alt="ILVORA Healthcare"><div><b>ILVORA HEALTHCARE GROUP</b><br>${esc(labels[type])}<br>Document No: ${esc(docNo)}</div></header><h1>${esc(labels[type])}</h1><p><b>Employee:</b> ${esc(employee.display_name)} (${esc(employee.username)})</p><p><b>Generated:</b> ${esc(new Date().toLocaleString('en-IN',{timeZone:'Asia/Kolkata'}))}</p><table>${details||'<tr><td colspan="2">No additional document details supplied</td></tr>'}</table>${signatureBlock}<div class="foot">This document was generated by ILVORA Workforce. Document ID: ${esc(docNo)}</div><script>window.addEventListener('load',()=>{document.title=${JSON.stringify(labels[type]+' '+docNo)}})</script></body></html>`;
    const id=crypto.randomUUID(), versions=Object.fromEntries((assets.results||[]).map(a=>[a.asset_key,a.version]));
    await env.DB.prepare(`INSERT INTO generated_documents(id,document_type,record_id,employee_user_id,branch_id,document_number,title,html_snapshot,asset_versions_json,generated_by,approved_by)
      VALUES(?,?,?,?,?,?,?,?,?,?,?)`).bind(id,type,data.record_id,employee.id,employee.branch_id,docNo,labels[type],html,JSON.stringify(versions),actor.id,source.approved_by||null).run();
    await audit(env,actor,'document.generated','generated_document',id,{document_type:type,document_number:docNo},request);
    return json({ok:true,id,document_number:docNo,title:labels[type],html,signature_applied:!!signature,seal_applied:!!seal,asset_versions:versions},201);
  }
  if(path==='/api/documents' && method==='GET') {
    if(!['managing_director','administrator','head_office_admin','branch_admin','employee'].includes(actor.role)) return json({error:'Access denied'},403);
    let sql='SELECT id,document_type,employee_user_id,branch_id,document_number,title,status,created_at FROM generated_documents',args=[];
    if(actor.role==='employee'){sql+=' WHERE employee_user_id=?';args.push(actor.id)}
    else if(actor.role==='branch_admin'){sql+=' WHERE branch_id=?';args.push(actor.branch_id)}
    sql+=' ORDER BY created_at DESC LIMIT 300';
    const rows=await env.DB.prepare(sql).bind(...args).all(); return json({documents:rows.results||[]});
  }
  const docMatch=path.match(/^\/api\/documents\/([A-Za-z0-9_-]+)$/);
  if(docMatch && method==='GET') {
    if(!['managing_director','administrator','head_office_admin','branch_admin','employee'].includes(actor.role))return json({error:'Access denied'},403);
    const row=await env.DB.prepare('SELECT * FROM generated_documents WHERE id=?').bind(docMatch[1]).first();
    if(!row) return json({error:'Document not found'},404);
    if(actor.role==='employee' && row.employee_user_id!==actor.id) return json({error:'Own documents only'},403);
    if(actor.role==='branch_admin' && row.branch_id!==actor.branch_id) return json({error:'Branch scope violation'},403);
    return new Response(row.html_snapshot,{headers:{'content-type':'text/html; charset=utf-8','cache-control':'no-store'}});
  }

  return json({error:"Not found"},404);
}

export default {
  async fetch(request,env) {
    const url=new URL(request.url);
    if(url.pathname.startsWith("/api/")) {
      try { return await handleApi(request,env); }
      catch(e) {
        console.error("API error",e);
        return json({error:"Server error. Check Worker logs."},500);
      }
    }
    if(url.pathname.startsWith("/modules/")) {
      const user=await currentUser(request,env);
      if(!user) return new Response("Authentication required",{status:401});
      if(user.must_change_password) return new Response("Password change required before accessing services",{status:403});
      if(!["managing_director","administrator"].includes(user.role)) {
        const state=await attendanceState(env,user);
        if(!state.marked) return new Response('<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Attendance required</title></head><body style="font:16px Arial;max-width:640px;margin:12vh auto;padding:24px;color:#203447"><h2>Attendance check-in required</h2><p>Mark your attendance from the ILVORA Workforce home page before opening your desk.</p><p><a href="/">Return to ILVORA Workforce</a></p></body></html>',{status:428,headers:{"content-type":"text/html; charset=utf-8"}});
      }
      const parts=url.pathname.split("/");
      const prefix=parts.length>=3?`modules/${parts[2]}/`:"";
      const allowed=await env.DB.prepare("SELECT 1 AS ok FROM role_module_access WHERE role=? AND module_prefix=?")
        .bind(user.role,prefix).first();
      if(!allowed) return new Response("Access denied",{status:403});
    }
    return env.ASSETS.fetch(request);
  }
};
