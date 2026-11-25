// Widget "Pockets" generado por Mis Finanzas
// Vuelve a copiarlo desde la app para actualizar los datos.
let DATA = {"mes":"noviembre 2026","actualizado":"25 nov, 20:29","pockets":[{"n":"Ocio","i":"👛","c":"#7c6cff","a":50,"g":12.4,"b":8.17,"uid":"rev-ocio"},{"n":"Gasolina","i":"👛","c":"#2ecc8f","a":0,"g":40,"b":25.9,"uid":"rev-gas"}]};
const SERVER = "https://finanzas-sync.juanbaezmican.workers.dev", PASS = "secreto123";
if (SERVER) { try { const rq = new Request(SERVER + '/api/widget'); rq.headers = { authorization: 'Bearer ' + PASS }; rq.timeoutInterval = 10; const j = await rq.loadJSON(); if (j && j.pockets && j.pockets.length) { DATA = j; const d = j.last_sync || j.updated; DATA.actualizado = d ? new Date(d).toLocaleString('es-ES', { day:'numeric', month:'short', hour:'2-digit', minute:'2-digit' }) : ''; } } catch (e) {} }
const leftOf = p => (p.b !== undefined && p.b !== null) ? p.b : (p.a - p.g);

function eur(n){ const neg=n<0; let [i,d]=Math.abs(n).toFixed(2).split('.'); i=i.replace(/\B(?=(\d{3})+(?!\d))/g,'.'); return (neg?'-':'')+i+','+d+' €'; }
function bar(frac, color, w){
  const h=6, dc=new DrawContext(); dc.size=new Size(w,h); dc.opaque=false; dc.respectScreenScale=true;
  let p=new Path(); p.addRoundedRect(new Rect(0,0,w,h),3,3); dc.addPath(p); dc.setFillColor(new Color('#86868b', 0.25)); dc.fillPath();
  const fw=Math.max(Math.min(frac,1)*w, frac>0?6:0);
  if(fw>0){ p=new Path(); p.addRoundedRect(new Rect(0,0,fw,h),3,3); dc.addPath(p); dc.setFillColor(new Color(frac>1?'#d70015':frac>=0.8?'#b64400':color)); dc.fillPath(); }
  return dc.getImage();
}
const fam = config.widgetFamily || 'medium';
const w = new ListWidget();
const C=(l,d)=>Color.dynamic(new Color(l),new Color(d));
w.backgroundColor = C('#ffffff','#1c1c1e');
w.setPadding(12,14,12,14);
const head = w.addStack(); head.centerAlignContent();
const t = head.addText('Pockets'); t.font=Font.semiboldSystemFont(13); t.textColor=C('#1d1d1f','#f5f5f7');
head.addSpacer();
const totalLeft = DATA.pockets.reduce((s,p)=>s+leftOf(p),0);
const tl = head.addText(eur(totalLeft)); tl.font=Font.boldSystemFont(13); tl.textColor=totalLeft<0?new Color('#d70015'):C('#248a3d','#30d158');
w.addSpacer(6);
const max = fam==='small' ? 3 : fam==='large' ? 10 : 4;
const barW = fam==='small' ? 120 : 280;
for (const p of DATA.pockets.slice(0,max)) {
  const row = w.addStack(); row.centerAlignContent();
  const n = row.addText(p.i+' '+p.n); n.font=Font.mediumSystemFont(11); n.textColor=C('#1d1d1f','#f5f5f7'); n.lineLimit=1;
  row.addSpacer();
  const left = leftOf(p);
  const v = row.addText(eur(left)); v.font=Font.boldSystemFont(11); v.textColor=left<0?new Color('#d70015'):C('#1d1d1f','#f5f5f7');
  w.addSpacer(3);
  w.addImage(bar(p.a?(p.a-left)/p.a:0, p.c, barW)).imageSize=new Size(barW,6);
  w.addSpacer(5);
}
w.addSpacer();
const f = w.addText([DATA.mes, DATA.actualizado].filter(Boolean).join(' · ')); f.font=Font.systemFont(9); f.textColor=new Color('#86868b');
Script.setWidget(w);
if (config.runsInApp) await w.presentMedium();
Script.complete();
