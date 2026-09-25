export async function onRequest(context) {
  try {
    return await handler(context);
  } catch (e) {
    return Response.json({error:e.message||"Server error"},{status:500});
  }
}
async function handler(ctx) {
  const url=new URL(ctx.request.url);
  const path=url.pathname.replace(/^\/api/,'')||'/';
  const method=ctx.request.method;
  const db=ctx.env.DB;
  const secret=ctx.env.AUTH_SECRET;
  if(!secret) throw new Error("AUTH_SECRET nonaktif. Tambahkan secret di Cloudflare Pages.");
  const user=await getUser(ctx);
  if(path==='/login'&&method==='POST'){
    const b=await ctx.request.json(); const u=await db.prepare("SELECT * FROM users WHERE username=?").bind(b.username).first();
    if(!u || !(await verifyPassword(b.password,u.password_hash))) return Response.json({error:"Username atau password salah."},{status:401});
    const token=await sign({id:u.id,username:u.username,role:u.role,exp:Date.now()+8*60*60*1000},secret);
    return new Response(JSON.stringify({user:{id:u.id,username:u.username,role:u.role}}),{headers:{"Content-Type":"application/json","Set-Cookie":cookie(token)}});
  }
  if(path==='/logout'&&method==='POST') return new Response(JSON.stringify({ok:true}),{headers:{"Content-Type":"application/json","Set-Cookie":"ss_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0"}});
  if(path==='/me'&&method==='GET'){if(!user)return Response.json({error:"Belum login"},{status:401});return Response.json({user:{id:user.id,username:user.username,role:user.role}})}
  if(!user) return Response.json({error:"Belum login."},{status:401});
  if(path==='/data'&&method==='GET'){
    const tx=await db.prepare("SELECT id,item,type,date,qty,note,created_by FROM transactions ORDER BY date DESC,id DESC").all();
    const us=user.role==='admin'?(await db.prepare("SELECT id,username,role FROM users ORDER BY username").all()).results:[];
    return Response.json({transactions:tx.results,users:us});
  }
  if(path==='/transactions'&&method==='POST'){const b=await ctx.request.json();validateTx(b);await ensureStock(db,b,null);await db.prepare("INSERT INTO transactions(item,type,date,qty,note,created_by) VALUES(?,?,?,?,?,?)").bind(b.item,b.type,b.date,b.qty,b.note||'',user.id).run();return Response.json({ok:true})}
  const tm=path.match(/^\/transactions\/(\d+)$/);
  if(tm){
    const id=Number(tm[1]);
    if(method==='DELETE'){await db.prepare("DELETE FROM transactions WHERE id=?").bind(id).run();return Response.json({ok:true})}
    if(method==='PUT'){const b=await ctx.request.json();validateTx(b);await ensureStock(db,b,id);await db.prepare("UPDATE transactions SET item=?,type=?,date=?,qty=?,note=? WHERE id=?").bind(b.item,b.type,b.date,b.qty,b.note||'',id).run();return Response.json({ok:true})}
  }
  if(path==='/users'&&method==='POST'){if(user.role!=='admin')return Response.json({error:"Admin saja."},{status:403});const b=await ctx.request.json();if(!/^[A-Za-z0-9_.-]{3,30}$/.test(b.username)||!b.password||b.password.length<6)throw new Error("Username 3-30 karakter dan password minimal 6 karakter.");const h=await hashPassword(b.password);await db.prepare("INSERT INTO users(username,password_hash,role) VALUES(?,?,?)").bind(b.username,h,b.role==='admin'?'admin':'user').run();return Response.json({ok:true})}
  if(path==='/password'&&method==='POST'){const b=await ctx.request.json();const u=await db.prepare("SELECT * FROM users WHERE id=?").bind(user.id).first();if(!(await verifyPassword(b.oldPassword,u.password_hash)))throw new Error("Password lama salah.");if(!b.newPassword||b.newPassword.length<6)throw new Error("Password baru minimal 6 karakter.");await db.prepare("UPDATE users SET password_hash=? WHERE id=?").bind(await hashPassword(b.newPassword),user.id).run();return Response.json({ok:true})}
  return Response.json({error:"Not found"},{status:404});
}
function validateTx(b){if(!['triplek','bambu','kayu','tambang','spon'].includes(b.item))throw new Error("Item tidak valid.");if(!['masuk','keluar'].includes(b.type))throw new Error("Jenis tidak valid.");if(!/^\\d{4}-\\d{2}-\\d{2}$/.test(b.date))throw new Error("Tanggal tidak valid.");if(!Number.isInteger(Number(b.qty))||Number(b.qty)<=0)throw new Error("Quantity tidak valid.")}
async function ensureStock(db,b,exclude){if(b.type!=='keluar')return;let q="SELECT COALESCE(SUM(CASE WHEN type='masuk' THEN qty ELSE -qty END),0) s FROM transactions WHERE item=?";let args=[b.item];if(exclude){q+=" AND id<>?";args.push(exclude)}const r=await db.prepare(q).bind(...args).first();if(Number(b.qty)>Number(r.s))throw new Error("Stock tidak mencukupi. Tersedia: "+r.s)}
function cookie(t){return `ss_session=${t}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=28800`}
function parseCookie(r){const c=r.headers.get("Cookie")||"";return Object.fromEntries(c.split(";").map(x=>x.trim().split("=")).filter(x=>x.length===2))}
async function getUser(ctx){const t=parseCookie(ctx.request).ss_session;if(!t)return null;const p=await verify(t,ctx.env.AUTH_SECRET).catch(()=>null);if(!p||p.exp<Date.now())return null;return p}
async function hashPassword(p){const salt=crypto.getRandomValues(new Uint8Array(16));const key=await crypto.subtle.importKey("raw",new TextEncoder().encode(p),"PBKDF2",false,["deriveBits"]);const bits=await crypto.subtle.deriveBits({name:"PBKDF2",salt,iterations:100000,hash:"SHA-256"},key,256);return "pbkdf2$100000$"+b64(salt)+"$"+b64(new Uint8Array(bits))}
async function verifyPassword(p,h){try{const [alg,it,s,b]=h.split("$");if(alg!=="pbkdf2")return false;const salt=ub64(s),key=await crypto.subtle.importKey("raw",new TextEncoder().encode(p),"PBKDF2",false,["deriveBits"]);const bits=await crypto.subtle.deriveBits({name:"PBKDF2",salt,iterations:+it,hash:"SHA-256"},key,256);return b64(new Uint8Array(bits))===b}catch{return false}}
async function sign(o,s){const raw=b64(new TextEncoder().encode(JSON.stringify(o)));const sig=await hmac(raw,s);return raw+"."+sig}
async function verify(t,s){const [raw,sig]=t.split(".");if(!raw||sig!==(await hmac(raw,s)))throw 0;return JSON.parse(new TextDecoder().decode(ub64(raw)))}
async function hmac(v,s){const k=await crypto.subtle.importKey("raw",new TextEncoder().encode(s),{name:"HMAC",hash:"SHA-256"},false,["sign"]);return b64(new Uint8Array(await crypto.subtle.sign("HMAC",k,new TextEncoder().encode(v))))}
function b64(a){let s="";for(const x of a)s+=String.fromCharCode(x);return btoa(s).replaceAll("+","-").replaceAll("/","_").replaceAll("=","")}
function ub64(s){s=s.replaceAll("-","+").replaceAll("_","/")+"==".slice(0,(4-s.length%4)%4);const x=atob(s);return Uint8Array.from(x,c=>c.charCodeAt(0))}
