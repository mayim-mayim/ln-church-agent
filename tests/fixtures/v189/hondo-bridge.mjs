// Isolated SDK/Hondo c1 bridge: actual handlers, in-memory persistence,
// synthetic provider/finality and read-only RPC. Never sends external traffic.
import {createRequire,registerHooks} from 'node:module';
import {pathToFileURL} from 'node:url';
import {createInterface} from 'node:readline';
const root=process.env.HONDO_ROOT;
const imp=p=>import(pathToFileURL(root+'/'+p).href);
const require=createRequire(root+'/package.json');
const viem=require('viem');
const payTo='0x'+'2'.repeat(40),tx='0x'+'a'.repeat(64);
const {PAYMENT_SURFACE_DISCOVERY_PROFILE}=await imp('backend/shared/task-venue/approved-task-offering-profiles.mjs');
console.log=()=>{}; console.error=()=>{}; console.warn=()=>{}; console.info=()=>{}; console.debug=()=>{};
globalThis.fetch=()=>{throw Error('External network prohibited in SDK integration');};
async function loadGateway(){
    globalThis.__v183GatewayViem=viem;
    const sources={
        'hono':`export class Hono {use(){return this}get(){return this}post(){return this}on(){return this}}`,
        'hono/aws-lambda':'export const handle=app=>app;',
        '@x402/hono':`export const paymentMiddleware=()=>async(c,next)=>next();export class x402ResourceServer {register(){return this}registerExtension(){return this}onAfterVerify(){return this}onBeforeSettle(){return this}onAfterSettle(){return this}onSettleFailure(){return this}}`,
        '@x402/evm/exact/server':'export class ExactEvmScheme {}',
        '@x402/svm/exact/server':'export class ExactSvmScheme {}',
        '@x402/extensions/bazaar':'export const bazaarResourceServerExtension={};export const declareDiscoveryExtension=v=>v;export const validateDiscoveryExtension=()=>({valid:true});',
        'viem':['recoverTypedDataAddress','parseAbi','decodeEventLog','encodeFunctionData','hashTypedData','createPublicClient','http','getAddress'].map(n=>`export const ${n}=(...args)=>globalThis.__v183GatewayViem.${n}(...args);`).join('\n'),
        '@aws-sdk/client-dynamodb':'export class DynamoDBClient {}',
        '@aws-sdk/lib-dynamodb':`export const DynamoDBDocumentClient={from(){return {send(){throw new Error('Unexpected AWS default I/O')}}}};
            ${['GetCommand','UpdateCommand','TransactWriteCommand','QueryCommand'].map(n=>`export class ${n} {constructor(input){this.input=input}}`).join('\n')}`,
        '@aws-sdk/client-lambda':'export class InvokeCommand {} export class LambdaClient {send(){throw new Error("Unexpected Lambda invoke")}}',
        '@aws-sdk/client-s3':'export class S3Client {}',
        '@x402/core/server':'export class HTTPFacilitatorClient {verify(){throw new Error("Unexpected default provider")}settle(){throw new Error("Unexpected default provider")}}',
        '@coinbase/x402':'export const facilitator={url:"https://invalid.example/",createAuthHeaders(){throw new Error("Unexpected auth operation")}};',
    };
    const hooks=registerHooks({resolve(specifier,context,next){return specifier in sources?{url:`v183gateway:${specifier}`,shortCircuit:true}:next(specifier,context);},
        load(url,context,next){return url.startsWith('v183gateway:')?{format:'module',shortCircuit:true,source:sources[url.slice(12)]}:next(url,context);}});
    const env={V17_TASK_DEFINITION_DIGEST:PAYMENT_SURFACE_DISCOVERY_PROFILE.definitionDigest,
        V17_TASK_MANIFEST_SHA256:'f'.repeat(64),V17_TASK_MANIFEST_URL:`https://kari.mayim-mayim.com/agent-task-specs/payment_surface_discovery.v1/1.0.0/${PAYMENT_SURFACE_DISCOVERY_PROFILE.definitionDigest}/manifest.json`,
        TASK_OFFER_REGISTRATION_PAY_TO:payTo};
    const previous=Object.fromEntries(Object.keys(env).map(key=>[key,process.env[key]]));Object.assign(process.env,env);
    try{return await imp('backend/Lambda/gishiki/Lambda_HonoGateway.js');}finally{hooks.deregister();for(const [key,value]of Object.entries(previous)){if(value===undefined)delete process.env[key];else process.env[key]=value;}}
}

const gateway=await loadGateway();
const {memoryImmediateStore}=await imp('tests/v183-execution-fixture.mjs');
const {choiceStore,key}=await imp('backend/shared/task-venue/endpoint-choice-reason-store.mjs');
const {createChoiceRegistrationService}=await imp('backend/shared/task-venue/endpoint-choice-reason-registration.mjs');
const {createImmediateVisitRegistrationService}=await imp('backend/shared/task-venue/immediate-visit-registration.mjs');
const {withRegistrationTiming}=await imp('backend/shared/task-venue/registration-timing.mjs');
const {finality}=await imp('tests/fixtures/v189/registration-evidence.mjs');
const {createRegistrationReadHandler,createRegistrationReadLookup,createRegistrationReadSignatureVerifier}=await imp('backend/shared/task-venue/registration-read-recovery.mjs');
const {createChoiceExecutionService}=await imp('backend/shared/task-venue/endpoint-choice-reason-execution.mjs');
const {createChoiceResults}=await imp('backend/shared/task-venue/endpoint-choice-reason-results.mjs');
const {createChoiceOwnerReadHandler}=await imp('backend/shared/task-venue/endpoint-choice-reason-owner-read.mjs');
const {createChoiceEvaluationService}=await imp('backend/shared/task-venue/endpoint-choice-reason-evaluation.mjs');
const {choiceHttp}=await imp('backend/shared/task-venue/endpoint-choice-reason-runtime.mjs');
let now=Date.now(),confirmed=true,settles=0,verifies=0,reads=0;
const physical=memoryImmediateStore();
const store=choiceStore(physical,async(taskId,{prefix='',cursor,limit=100}={})=>{
 const rows=[...physical.rows.entries()].filter(([k,v])=>k.startsWith('reports|')&&v.PK===key(taskId).PK&&v.SK.startsWith(prefix)&&(!cursor||v.SK>cursor.SK)).map(x=>x[1]).sort((a,b)=>a.SK.localeCompare(b.SK));
 const items=rows.slice(0,limit);return {items:structuredClone(items),cursor:rows.length>limit?{PK:items.at(-1).PK,SK:items.at(-1).SK}:null};});
const chainReadback=async i=>confirmed?finality(i,tx):{};
const choice=createChoiceRegistrationService({store,clock:()=>now,chainReadback});
const immediate=createImmediateVisitRegistrationService({store:physical,clock:()=>now,chainReadback});
const providers={verify:async p=>{verifies++;return {isValid:true,payer:p.payload.authorization.from};},
 settle:async p=>{settles++;return {success:true,network:'eip155:8453',transaction:tx,payer:p.payload.authorization.from};}};
const options=service=>({serviceFactory:async()=>service,payTo:()=>payTo,reconcile:id=>service.reconcile(id),gate:async()=>{},assertFacilitatorReady:async()=>{},providerClient:providers});
const handlers={choice:gateway.createChoiceRegistrationHandler(options(choice)),immediate:gateway.createImmediateVisitRegistrationHandler(options(immediate))};
process.env.IMMEDIATE_VISIT_V2_REGISTRATION_ENABLED='true';
const keys=async()=>({activeKeyId:'fixture',keys:new Map([['fixture',Buffer.alloc(32,7)]])});
let contractCode='0x',contractValid=true,rpcFails=false;
const verifier=createRegistrationReadSignatureVerifier({viem,client:async()=>({getChainId:async()=>8453,getCode:async()=>{if(rpcFails)throw Error('fixture');return contractCode;},readContract:async()=>contractValid?'0x1626ba7e':'0xffffffff'})});
const read=createRegistrationReadHandler({keys,verifySignature:verifier,lookup:createRegistrationReadLookup({getKey:i=>{reads++;return physical.getKey({...i,table:'tasks'});}}),clock:()=>now});
const {createImmediateVisitExecutionService,immediateVisitErrorResponse}=await imp('backend/shared/task-venue/immediate-visit-execution.mjs');
const {immediateVisitTaskProjection}=await imp('backend/shared/task-venue/immediate-visit-core.mjs');
const immediateExecution=createImmediateVisitExecutionService({store:physical,clock:()=>now,checksumAddress:viem.getAddress});
const execution=createChoiceExecutionService({store,clock:()=>now,checksumAddress:viem.getAddress});
const results=createChoiceResults({store,lifecycle:execution,clock:()=>now});
const ownerRead=createChoiceOwnerReadHandler({keys,verifySignature:verifier,results,clock:()=>now});
let evaluationQ='0';
const evaluation=createChoiceEvaluationService({store,clock:()=>now,adapter:async()=>({q:evaluationQ,returned_model:'jev-1.13.0',usage:{}})});
const runtime={store,execution,results,ownerRead,evaluation};
function event(x){return {rawPath:x.path,rawQueryString:x.query??'',headers:x.headers,httpMethod:x.method,body:x.body,requestContext:{http:{method:x.method},requestId:'sdk-isolated'}};}
async function run(x){
 if(x.control==='counts')return {settles,verifies,reads,now};
 if(x.control==='configure'){if(x.confirmed!==undefined)confirmed=x.confirmed;if(x.advance)now+=x.advance;if(x.contractCode!==undefined)contractCode=x.contractCode;if(x.contractValid!==undefined)contractValid=x.contractValid;if(x.rpcFails!==undefined)rpcFails=x.rpcFails;return {now};}
 if(x.control==='reconcile')return {state:(await (x.type==='endpoint_choice_reason.v1'?choice:immediate).reconcile(x.ref)).business_commit_state};
 if(x.control==='evaluate'){evaluationQ=x.q??'0';await evaluation.run({task_id:x.task,execution_id:x.execution});return {};}
 if(x.control==='delete-descriptions'){return {deleted:await results.deleteDescriptions(x.task)};}
 const body=x.body?JSON.parse(x.body):null;
 if(x.path==='/api/bazaar/task-offers'){
  const h=body.task_type==='endpoint_choice_reason.v1'?handlers.choice:handlers.immediate;
  const headers=Object.fromEntries(Object.entries(x.headers).map(([k,v])=>[k.toLowerCase(),v]));
  const ctx={get:n=>['choiceRequest','immediateVisitRequest'].includes(n)?body:undefined,req:{header:n=>headers[n.toLowerCase()],method:'POST',path:'/bazaar/task-offers'},json:(body,status,headers)=>({status,body,headers:headers??{}})};
  return withRegistrationTiming({budgetValid:true,deadline:Date.now()+120000},()=>h(ctx));
 }
 if(x.path.startsWith('/api/agent/task-offer-registration-recovery/'))return read(event(x));
 if(x.path.startsWith('/api/agent/task-offer-results/'))return ownerRead(event(x));
 const match=x.path.match(/^\/api\/agent\/tasks\/([^/]+)(.*)$/);
 if(match){
  const im=await physical.get(match[1]);
  if(im){
   const headers=Object.fromEntries(Object.entries(x.headers).map(([k,v])=>[k.toLowerCase(),v]));
   const input={taskId:match[1],body,claimToken:headers['x-ln-task-claim-token'],idempotencyKey:headers['idempotency-key']};
   try{
    if(match[2]==='')return {status:200,body:immediateVisitTaskProjection(im,now)};
    if(match[2]==='/claim')return {status:200,body:await immediateExecution[headers['x-ln-claim-recovery']?'readClaim':'claim'](input)};
    if(match[2]==='/completion'){const r=await immediateExecution.report(input);return {status:r.http_status,body:r.body};}
    const sub=match[2].match(/^\/submissions\/([^/]+)\/status$/);
    if(sub)return {status:200,body:await immediateExecution.status({...input,submissionId:sub[1]})};
   }catch(e){return immediateVisitErrorResponse(e,'sdk',im.task_type);}
  }
  const e=event(x);e.pathParameters={task_id:match[1]};let action;
  if(match[2]==='')action='detail';
  else if(match[2]==='/claim')action=Object.keys(x.headers).some(k=>k.toLowerCase()==='x-ln-claim-recovery')?'claim-read':'claim';
  else if(match[2]==='/claim/abandon')action='abandon';
  else if(match[2]==='/completion')action='completion';
  else if(match[2]==='/results')action='results';
  else {const sub=match[2].match(/^\/submissions\/([^/]+)\/status$/);if(sub){action='status';e.pathParameters.submission_id=sub[1];}}
  if(action)return choiceHttp(action,e,{runtimeFactory:async()=>runtime});
 }
 throw Error('Unsupported isolated route');
}
for await(const line of createInterface({input:process.stdin,crlfDelay:Infinity})){
 try{const result=await run(JSON.parse(line));process.stdout.write(JSON.stringify(result)+'\n');}
 catch(e){process.stdout.write(JSON.stringify({bridge_error:e.name,code:e.code??null})+'\n');}
}
