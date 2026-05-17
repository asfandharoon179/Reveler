pdfjsLib.GlobalWorkerOptions.workerSrc='https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js';

const PATTERNS=[
  {p:/ignore\s+(previous|all|above|prior)\s+instructions?/i,l:'IGNORE_INSTRUCTIONS'},
  {p:/give\s+(fake|false|incorrect)\s+data/i,l:'FAKE_DATA'},
  {p:/do\s+not\s+mention/i,l:'SUPPRESSION'},
  {p:/hidden\s+prompt/i,l:'HIDDEN_PROMPT'},
  {p:/ai\s+instruction/i,l:'AI_INSTRUCTION'},
  {p:/system\s+prompt/i,l:'SYSTEM_PROMPT'},
  {p:/you\s+are\s+(now|a|an)\s+/i,l:'PERSONA_INJECTION'},
  {p:/act\s+as\s+(a|an|if)/i,l:'ROLE_INJECTION'},
  {p:/disregard\s+(previous|all|any)/i,l:'DISREGARD'},
  {p:/\[INST\]|\[\/INST\]|<\|im_start\|>/i,l:'LLM_TOKEN'},
  {p:/jailbreak|DAN\s+mode|developer\s+mode/i,l:'JAILBREAK'},
  {p:/print\s+(your|the)\s+(system|prompt)/i,l:'PROMPT_EXTRACTION'},
  {p:/do\s+not\s+(tell|reveal|show)/i,l:'SECRECY'},
  {p:/always\s+(respond|say|reply)\s+with/i,l:'OVERRIDE'},
  {p:/you\s+must\s+(never|always|only)/i,l:'IMPERATIVE'},
];

let allBlocks=[],rawText='',revealOnly=false,currentFile='';

const uploadZone=document.getElementById('uploadZone');
const fileInput=document.getElementById('fileInput');
const progressBar=document.getElementById('progressBar');
const progressFill=document.getElementById('progressFill');
const statusTxt=document.getElementById('statusTxt');

uploadZone.addEventListener('dragover',e=>{e.preventDefault();uploadZone.classList.add('drag-over')});
uploadZone.addEventListener('dragleave',()=>uploadZone.classList.remove('drag-over'));
uploadZone.addEventListener('drop',e=>{e.preventDefault();uploadZone.classList.remove('drag-over');if(e.dataTransfer.files[0])handleFile(e.dataTransfer.files[0])});
uploadZone.addEventListener('click',()=>fileInput.click());
document.getElementById('uploadBtn').addEventListener('click',e=>{e.stopPropagation();fileInput.click()});
fileInput.addEventListener('change',e=>{if(e.target.files[0])handleFile(e.target.files[0])});
document.getElementById('newScanBtn').addEventListener('click',resetAll);
document.getElementById('analyzeAnotherBtn').addEventListener('click',resetAll);
document.getElementById('returnHomeBtn').addEventListener('click',()=>{resetAll();document.getElementById('home').scrollIntoView({behavior:'smooth'})});

function setProgress(v,msg){progressBar.style.display='block';progressFill.style.width=v+'%';statusTxt.style.display='block';statusTxt.textContent=msg}

async function handleFile(file){
  const ext=file.name.split('.').pop().toLowerCase();
  if(!['pdf','docx','doc'].includes(ext)){alert('Only PDF and DOCX files are supported.');return}
  currentFile=file.name;
  setProgress(10,'Reading file...');
  try{
    let blocks=ext==='pdf'?await extractPDF(file):await extractDOCX(file);
    setProgress(90,'Running threat analysis...');
    await new Promise(r=>setTimeout(r,250));
    allBlocks=blocks.map(analyzeBlock);
    rawText=allBlocks.map(b=>b.text).join('\n');
    setProgress(100,'Complete!');
    setTimeout(showResults,400);
  }catch(err){setProgress(0,'Error: '+err.message);console.error(err)}
}

async function extractPDF(file){
  const ab=await file.arrayBuffer();
  const pdf=await pdfjsLib.getDocument({data:ab}).promise;
  const blocks=[];
  for(let p=1;p<=pdf.numPages;p++){
    setProgress(10+Math.round((p/pdf.numPages)*70),`Scanning page ${p} of ${pdf.numPages}...`);
    const page=await pdf.getPage(p);
    const content=await page.getTextContent();
    const vp=page.getViewport({scale:1});
    content.items.forEach(item=>{
      if(!item.str||!item.str.trim())return;
      const t=item.transform||[];const x=t[4]??null;const y=t[5]??null;const fs=item.height||0;
      const flags=[];
      if(fs>0&&fs<4)flags.push('TINY_FONT');
      if(fs===0)flags.push('ZERO_FONT');
      if(x!==null&&(x<-50||x>vp.width+50))flags.push('OFF_PAGE');
      blocks.push({text:item.str,page:p,fontSize:fs,flags,source:'pdf'});
    });
    try{
      const ops=await page.getOperatorList();
      let whiteActive=false;
      const pageBlocks=blocks.filter(b=>b.page===p);
      let blockPointer=0;
      for(let i=0;i<ops.fnArray.length;i++){
        if(ops.fnArray[i]===45){const a=ops.argsArray[i];whiteActive=!!(a&&a[0]>0.9&&a[1]>0.9&&a[2]>0.9);}
        if(whiteActive&&(ops.fnArray[i]===49||ops.fnArray[i]===50||ops.fnArray[i]===14)){
          if(blockPointer<pageBlocks.length){if(!pageBlocks[blockPointer].flags.includes('WHITE_COLOR'))pageBlocks[blockPointer].flags.push('WHITE_COLOR');blockPointer++;}
        }
      }
    }catch(_){}
  }
  return blocks;
}

async function extractDOCX(file){
  setProgress(40,'Parsing DOCX structure...');
  const ab=await file.arrayBuffer();

  // Read raw XML from docx zip
  const {JSZip} = window;
  let whiteParas=new Set();
  try{
    const zip=await JSZip.loadAsync(ab);
    const xmlStr=await zip.file('word/document.xml').async('string');
    // Find paragraphs with white color (FFFFFF or ffffff or white)
    const parser=new DOMParser();
    const xmlDoc=parser.parseFromString(xmlStr,'application/xml');
    const runs=xmlDoc.querySelectorAll('r');
    runs.forEach(run=>{
      const color=run.querySelector('color');
      if(color){
        const val=color.getAttribute('w:val')||'';
        if(/^(ffffff|FFFFFF|white)$/i.test(val.trim())){
          // get parent paragraph index
          const para=run.closest('p');
          if(para)whiteParas.add(para);
        }
      }
    });
  }catch(e){console.warn('XML parse failed',e)}

  const raw=await mammoth.extractRawText({arrayBuffer:ab});
  const lines=raw.value.split('\n').filter(l=>l.trim());

  // Re-parse to map lines to paragraphs
  const ab2=await file.arrayBuffer();
  const zip2=await (await JSZip.loadAsync(ab2));
  let paraTexts=[];
  try{
    const xmlStr=await zip2.file('word/document.xml').async('string');
    const parser=new DOMParser();
    const xmlDoc=parser.parseFromString(xmlStr,'application/xml');
    const paras=xmlDoc.querySelectorAll('p');
    paras.forEach(para=>{
      const text=Array.from(para.querySelectorAll('t')).map(t=>t.textContent).join('').trim();
      if(!text)return;
      const hasWhite=[...para.querySelectorAll('color')].some(c=>{
        const val=(c.getAttribute('w:val')||'').trim();
        return /^(ffffff|FFFFFF)$/i.test(val);
      });
      paraTexts.push({text,hasWhite});
    });
  }catch(e){console.warn('para parse failed',e)}

  // Match extracted lines to para data
  return lines.map((l,i)=>{
    const match=paraTexts.find(p=>p.text===l.trim());
    const flags=[];
    if(match&&match.hasWhite)flags.push('WHITE_COLOR');
    return{text:l,page:null,fontSize:null,flags,source:'docx',index:i};
  });
}

function analyzeBlock(block){
  const threats=[...(block.flags||[])];
  let isSuspicious=false;
  let isHidden=false;

  // Any hiding flag → mark as hidden AND suspicious
  const hiddenFlags=['WHITE_COLOR','CSS_DISPLAY_NONE','CSS_HIDDEN','CSS_VISIBILITY_HIDDEN','ZERO_OPACITY','ZERO_FONT_SIZE','TINY_FONT','ZERO_FONT','OFF_PAGE'];
  if(block.flags&&block.flags.some(f=>hiddenFlags.includes(f))){isHidden=true;isSuspicious=true;}

  PATTERNS.forEach(({p,l})=>{if(p.test(block.text)){isSuspicious=true;threats.push(l)}});
  if(/[\u200B-\u200F\u202A-\u202E\uFEFF]/.test(block.text)){isHidden=true;isSuspicious=true;threats.push('UNICODE_TRICK')}
  if(/^[A-Za-z0-9+/]{40,}={0,2}$/.test(block.text.trim())){isSuspicious=true;threats.push('BASE64')}

  return{...block,isSuspicious,isHidden,threats};
}

function showResults(){
  document.getElementById('homepage').style.display='none';
  document.getElementById('outputSection').style.display='block';
  document.getElementById('thankyouPage').style.display='block';
  document.getElementById('outputFilename').textContent=currentFile;
  window.scrollTo({top:0,behavior:'smooth'});
  document.getElementById('sTotal').textContent=allBlocks.length;
  document.getElementById('sChars').textContent=rawText.length.toLocaleString();
  document.getElementById('sSusp').textContent=allBlocks.filter(b=>b.isSuspicious).length;
  document.getElementById('sHidden').textContent=allBlocks.filter(b=>b.isHidden).length;
  const tm={};allBlocks.forEach(b=>b.threats.forEach(t=>{tm[t]=(tm[t]||0)+1}));
  if(Object.keys(tm).length>0){
    document.getElementById('threatsBox').style.display='block';
    document.getElementById('threatsList').innerHTML=Object.entries(tm).map(([l,c])=>`<div class="threat-item">⚡ ${l} — ${c} occurrence(s)</div>`).join('');
  }
  renderBlocks(allBlocks,'');
}

function renderBlocks(blocks,query){
 const filtered=revealOnly?blocks.filter(b=>b.isSuspicious):blocks;
  const searched=query?filtered.filter(b=>b.text.toLowerCase().includes(query.toLowerCase())):filtered;
  document.getElementById('blockCount').textContent=searched.length+' / '+allBlocks.length+' blocks';
  if(!searched.length){document.getElementById('panelBody').innerHTML='<div style="color:var(--muted);text-align:center;padding:2rem;font-family:var(--font)">No matching blocks found.</div>';return}
  let html='';let lastPage=null;
  searched.forEach(b=>{
    if(b.page&&b.page!==lastPage){html+=`<div style="font-size:10px;color:var(--muted);padding:6px 8px 2px;letter-spacing:1px;font-family:var(--font)">— PAGE ${b.page} —</div>`;lastPage=b.page}
    const cls=b.isSuspicious?'txt-block suspicious':b.isHidden?'txt-block hidden-txt':'txt-block';
    let txt=b.text.replace(/</g,'&lt;').replace(/>/g,'&gt;');
    if(query){const re=new RegExp('('+query.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')+')','gi');txt=txt.replace(re,'<mark class="highlight">$1</mark>')}
    const badges=b.threats.map(t=>`<span class="w-badge">${t}</span>`).join('');
    html+=`<div class="${cls}">${txt}${badges}</div>`;
  });
  document.getElementById('panelBody').innerHTML=html;
}

document.getElementById('searchInput').addEventListener('input',e=>renderBlocks(allBlocks,e.target.value));
document.getElementById('copyBtn').addEventListener('click',()=>{navigator.clipboard.writeText(rawText);const b=document.getElementById('copyBtn');b.textContent='✓ Copied!';setTimeout(()=>b.textContent='⎘ Copy All',2000)});
document.getElementById('downloadBtn').addEventListener('click',()=>{
  let r=`PROMPTREVEAL ANALYSIS REPORT\n${'='.repeat(40)}\nFile: ${currentFile}\nTotal Blocks: ${allBlocks.length}\nSuspicious: ${allBlocks.filter(b=>b.isSuspicious).length}\nHidden: ${allBlocks.filter(b=>b.isHidden).length}\nGenerated: ${new Date().toLocaleString()}\n${'='.repeat(40)}\n\n`;
  const threats=allBlocks.filter(b=>b.isSuspicious||b.isHidden);
  if(threats.length){r+=`THREATS DETECTED:\n${'-'.repeat(30)}\n`;threats.forEach(b=>r+=`[${b.threats.join(', ')}] ${b.text}\n`);r+=`\n${'='.repeat(40)}\n\n`}
  r+=`FULL EXTRACTED TEXT:\n${'-'.repeat(30)}\n${rawText}`;
  const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([r],{type:'text/plain'}));a.download='promptreveal-report.txt';a.click();
});
document.getElementById('revealBtn').addEventListener('click',()=>{
  revealOnly=!revealOnly;
  const btn=document.getElementById('revealBtn');
  btn.textContent=revealOnly?'👁 Show All Text':'👁 Show Suspicious Only';
  btn.style.background=revealOnly?'#fff':'var(--red)';
  btn.style.color=revealOnly?'var(--text)':'#fff';
  btn.style.borderColor=revealOnly?'var(--border)':'var(--red)';
  renderBlocks(allBlocks,document.getElementById('searchInput').value);
});

function resetAll(){
  allBlocks=[];rawText='';revealOnly=false;currentFile='';
  document.getElementById('homepage').style.display='block';
  document.getElementById('outputSection').style.display='none';
  document.getElementById('thankyouPage').style.display='none';
  document.getElementById('threatsBox').style.display='none';
  document.getElementById('revealBtn').textContent='👁 Show Suspicious Only';
  document.getElementById('revealBtn').className='btn btn-red';
  progressBar.style.display='none';statusTxt.style.display='none';
  progressFill.style.width='0%';fileInput.value='';
  document.getElementById('searchInput').value='';
  window.scrollTo({top:0,behavior:'smooth'});
}
