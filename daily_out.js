// Aviso diario de gastos generado por Mis Finanzas
// Contiene la contraseña de tu servidor: no lo compartas.
const SERVER = "https://finanzas-sync.juanbaezmican.workers.dev", PASS = "secreto123", APP = "http://app.test/index.html";
let j;
try {
  const rq = new Request(SERVER + '/api/today?refresh=1');
  rq.headers = { authorization: 'Bearer ' + PASS };
  rq.timeoutInterval = 45;
  j = await rq.loadJSON();
  if (!j || !j.body) throw new Error(j && j.error ? j.error : 'sin datos');
} catch (e) {
  j = { title: 'Mis Finanzas', body: 'No he podido consultar tus gastos de hoy (' + e.message + ').' };
}
const n = new Notification();
n.title = j.title;
n.body = j.body;
if (APP) n.openURL = APP;
await n.schedule();
Script.complete();
