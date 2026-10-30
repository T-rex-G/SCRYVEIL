// Synthetic architecture spike, not a production parser. Node type stripping only.
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
type Input = {app: string; domain: string; timestamp: string};
const start = performance.now();
const data = readFileSync(process.argv[2]);
const rows: string[][] = data.toString('utf8').trim().split('\n').map(line => {
  const r = JSON.parse(line) as Input;
  return [r.app, r.domain.toLowerCase().replace(/\.$/, ''), new Date(r.timestamp).toISOString()];
});
rows.sort((a,b) => {
  for(let i=0;i<3;i++){if(a[i]<b[i])return -1; if(a[i]>b[i])return 1;} return 0;
});
const output = JSON.stringify(rows);
console.log(JSON.stringify({input_sha256:createHash('sha256').update(data).digest('hex'),
  output_sha256:createHash('sha256').update(output).digest('hex'), records:rows.length,
  seconds:(performance.now()-start)/1000, peak_rss_kib:process.resourceUsage().maxRSS}));
