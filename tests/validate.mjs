import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
const root=process.cwd();
const fail=[];
const check=(condition,message)=>{if(!condition)fail.push(message)};
for(const file of ['src/worker.js','public/assets/workspace-runtime.js']){
 const r=spawnSync(process.execPath,['--check',file],{cwd:root,encoding:'utf8'});
 check(r.status===0,`${file} syntax check failed: ${r.stderr}`);
}
const rbac=JSON.parse(fs.readFileSync('config-rbac.json','utf8'));
check(rbac.policy==='default-deny','RBAC must remain default-deny');
check(rbac.module_access.attendance_marker?.length===1,'Attendance Marker must have only its dedicated capture module');
for(const role of ['employee','branch_admin','head_office_admin','administrator']){
 const all=rbac.module_access[role]||[];
 check(!all.some(x=>x.includes('signatory-payroll-experience')) ,`${role} must not receive MD signatory module access`);
}
const worker=fs.readFileSync('src/worker.js','utf8');
check(worker.includes("if(actor.role!=='managing_director') return json({error:'Managing Director access only'},403)"),'MD signatory API must enforce MD-only access');
check(worker.includes('Final resignation approval is reserved for the Managing Director'),'MD final resignation approval guard missing');
check(worker.includes('Advances above 25% of approved monthly salary require Managing Director approval'),'25% advance approval guard missing');
check(worker.includes('Branch Admin approval is limited to leave requests of up to 5 calendar days'),'5-day leave approval guard missing');
const runtime=fs.readFileSync('public/assets/workspace-runtime.js','utf8');
check(runtime.includes('ilvora-healthcare-logo.png'),'Printable logo reference missing');
check(runtime.includes('for(const child of main.children){if(child!==root&&!child.dataset.livePanel)child.hidden=true;}'),'Legacy sample/prototype page content must be superseded by the operational workspace');
const workflow=fs.readFileSync('.github/workflows/deploy.yml','utf8');
check(!/^\s*push\s*:/m.test(workflow),'Deployment workflow must not deploy automatically on push');
check(workflow.includes("inputs.confirm_deploy == 'DEPLOY'"),'Manual deployment must require explicit DEPLOY confirmation');
const modules=path.join(root,'public','modules');
let pages=[];
function walk(dir){for(const e of fs.readdirSync(dir,{withFileTypes:true})){const p=path.join(dir,e.name);if(e.isDirectory())walk(p);else if(/\.html?$/i.test(e.name))pages.push(p)}}
walk(modules);
check(pages.length>=48,`Expected at least 48 original module pages; found ${pages.length}`);
for(const p of pages){
 const html=fs.readFileSync(p,'utf8');
 if(!p.includes('signatory-payroll-experience-prototype-v2')) check(html.includes('workspace-runtime.js'),`Shared workspace runtime missing from ${path.relative(root,p)}`);
 const m=html.match(/<script[^>]+src=["']([^"']*workspace-runtime\.js)["']/i);
 if(m){const resolved=path.resolve(path.dirname(p),m[1]);check(fs.existsSync(resolved),`Broken workspace runtime reference in ${path.relative(root,p)}`)}
}
check(fs.existsSync('migrations/0002_workforce_operations.sql'),'Operational D1 migration missing');
check(fs.existsSync('migrations/0003_head_office_attendance_gate.sql'),'Head Office and attendance gate migration missing');
check(worker.includes('/api/auth/attendance-checkin'),'Attendance check-in endpoint missing');
check(worker.includes('Only the Managing Director or Administrator may create a branch'),'Branch creation MD/Admin guard missing');
check(worker.includes('Attendance is required before accessing your ILVORA Workforce desk'),'API attendance desk gate missing');
check(worker.includes('attendanceState(env,user)'),'Static module attendance gate missing');
check(worker.includes('15*60*1000'),'OTP validity must be 15 minutes');
check(worker.includes('/api/auth/otp/resend'),'OTP resend endpoint missing');
check(worker.includes('/api/auth/otp/reset-password'),'Dual-channel OTP password reset endpoint missing');
check(worker.includes('OTP_PEPPER'),'OTP HMAC secret requirement missing');
check(worker.includes('generateInitialPassword'),'Server-side automatic initial password generation missing');
check(worker.includes('credential_delivery:"email"'),'Initial password email delivery audit missing');
check(worker.includes('registered_email') && worker.includes('registered_mobile'),'Registered email/mobile matching missing');
check(fs.readFileSync('public/index.html','utf8').includes('Resend OTP'),'Resend OTP user interface missing');
check(fs.existsSync('migrations/0004_auth_otp_contacts.sql'),'OTP/contact migration missing');
check(worker.includes('WHERE status=\'active\' ORDER BY name'),'Inactive branches must be excluded from branch selection');
check(fs.readFileSync('public/index.html','utf8').includes('Capture GPS & Mark Attendance'),'Login attendance gate UI missing');
check(fs.readFileSync('public/assets/workspace-runtime.js','utf8').includes('Create branch'),'MD/Administrator branch creation UI missing');
const migration=fs.readFileSync('migrations/0003_head_office_attendance_gate.sql','utf8');
check(migration.includes("UPDATE branches SET status='inactive' WHERE id<>'branch_kochi'"),'Non-Head Office branches must be deactivated');
check(migration.includes("UPDATE users SET branch_id='branch_kochi'"),'Existing non-executive accounts must be reassigned to Head Office');
if(fail.length){console.error('ILVORA validation FAILED');for(const x of fail)console.error(' - '+x);process.exit(1)}
console.log(`ILVORA static validation PASSED: ${pages.length} module pages, syntax, RBAC guards, manual-deploy safeguard and migration presence.`);
