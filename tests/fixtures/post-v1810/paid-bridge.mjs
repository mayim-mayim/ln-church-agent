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

const hash=tx;
const {privateKeyToAccount}=require('viem/accounts');
const account=privateKeyToAccount('0x'+'17'.repeat(32)),payer=account.address.toLowerCase();
const {harness,finality}=await imp('tests/v185-fixture.mjs');
const {createPaidSampleService,createSampleTokens,sampleReferenceV2,sampleKey}=await imp('backend/shared/task-venue/paid-service-trial-sample.mjs');
const {createSampleRecoveryHandler}=await imp('backend/shared/task-venue/paid-service-trial-sample-recovery.mjs');
const {createPaidTrialRegistrationService,paidRegistrationChallenge}=await imp('backend/shared/task-venue/paid-service-trial-registration.mjs');
const {createPaidExecutionService,createPaidExecutionHandler}=await imp('backend/shared/task-venue/paid-service-trial-execution.mjs');
const {createPaidEvaluationService}=await imp('backend/shared/task-venue/paid-service-trial-evaluation.mjs');
const {purchaseTypedData}=await imp('backend/shared/task-venue/paid-service-trial-runtime.mjs');
const {taskProjection,ASSET,NETWORK}=await imp('backend/shared/task-venue/paid-service-trial-core.mjs');
const {verifyExternalPurchase,PURCHASE_ABI}=await imp('backend/shared/task-venue/paid-service-trial-witness.mjs');
const {withRegistrationTiming}=await imp('backend/shared/task-venue/registration-timing.mjs');
const {createRegistrationReadLookup}=await imp('backend/shared/task-venue/registration-read-recovery.mjs');
const tokens=createSampleTokens(async()=>({activeKeyId:'test',keys:new Map([['test',Buffer.alloc(32,7)]])}));
let now=Date.now(),h=harness(),samplePaid=0,agentPaid=0,feeSettles=0,purchased,taskId,tuple;
const clock=()=>now,requirements={scheme:'exact',network:NETWORK,asset:ASSET,amount:'100000',payTo,maxTimeoutSeconds:300,extra:{name:'USD Coin',version:'2'}};
const seller=()=>({status:402,headers:{'payment-required':Buffer.from(JSON.stringify({x402Version:2,resource:{url:'https://seller.example/data'},accepts:[requirements]})).toString('base64')},body:Buffer.alloc(0),bodyComplete:true});
const samples=createPaidSampleService({store:h.store,tokens,clock,fetcher:async(url,o)=>{if(url!=='https://seller.example/data')throw Error('Unexpected seller');await o.beforeDispatch?.();if(o.paymentSignature){samplePaid++;throw Error('Synthetic response lost');}return seller();},verifySignature:async(p,s)=>{if((await viem.recoverTypedDataAddress({...purchaseTypedData(p),signature:s})).toLowerCase()!==p.payer)throw Error('Invalid synthetic signature');return true;}});
const execution=createPaidExecutionService({store:h.store,clock}),evaluation=createPaidEvaluationService({store:h.store,clock});
const sampleRead=createSampleRecoveryHandler({store:h.store,samples,tokens,clock,readSignature:async(t,s)=>{if((await viem.recoverTypedDataAddress({...t,signature:s})).toLowerCase()!==t.message.payer)throw Error('Invalid read signature');}});
function chain(p,now){
 const blockHash='0x'+'d'.repeat(64),tx={hash,to:ASSET,from:'0x'+'f'.repeat(40),input:viem.encodeFunctionData({abi:PURCHASE_ABI,functionName:'transferWithAuthorization',args:[p.payer,p.payTo,BigInt(p.amount),BigInt(p.validAfter),BigInt(p.validBefore),p.authorization_nonce,'0x1234']}),blockHash,blockNumber:'0x64',transactionIndex:'0x0'};
 const identity={transactionHash:hash,blockHash,blockNumber:'0x64',transactionIndex:'0x0',address:ASSET,removed:false};
 const logs=[{...identity,logIndex:'0x0',topics:viem.encodeEventTopics({abi:PURCHASE_ABI,eventName:'AuthorizationUsed',args:{authorizer:p.payer,nonce:p.authorization_nonce}}),data:'0x'},{...identity,logIndex:'0x1',topics:viem.encodeEventTopics({abi:PURCHASE_ABI,eventName:'Transfer',args:{from:p.payer,to:p.payTo}}),data:viem.encodeAbiParameters([{type:'uint256'}],[BigInt(p.amount)])}];
 return async(method,params)=>{
  if(method==='eth_chainId')return '0x2105';if(method==='eth_getCode')return '0x';if(method==='eth_getTransactionByHash')return tx;if(method==='eth_getTransactionReceipt')return {...identity,status:'0x1',logs};if(method==='eth_getLogs')return logs.slice(0,1);
  if(method==='eth_getBlockByNumber'){const n=params[0]==='latest'||params[0]==='safe'?100:Number(BigInt(params[0]));return {number:'0x'+n.toString(16),timestamp:'0x'+(BigInt(Math.floor(now/1000))+BigInt(n-99)).toString(16),hash:blockHash,parentHash:'0x'+'e'.repeat(64),stateRoot:blockHash,receiptsRoot:blockHash,transactionsRoot:blockHash,nonce:'0x0000000000000000',logsBloom:'0x'+'0'.repeat(512),gasLimit:'0x100000',gasUsed:'0x100',size:'0x1000',transactions:n===100?[hash]:[]};}
  throw Error('Unexpected RPC '+method);
 };
}
async function witnessSample(ref,p){
 const record=await h.store.getKey(sampleKey(ref));
 const witness=await verifyExternalPurchase({rpc:chain(p,now),purchase:p,transactionHash:hash,termsDigest:record.purchase_terms_digest});
 if(witness.state!=='VERIFIED')throw Error('Synthetic witness '+JSON.stringify(witness));
 await samples.complete(record,witness,now);return samples.result(await h.store.getKey(sampleKey(ref)));
}
async function setup(method){
 now=Date.now();
 const t=await samples.sampleTerms({schema_version:'ln_church.paid_service_trial_sample_terms_request.v3',request_input:{method,url:'https://seller.example/data',body:method==='POST'?'{"z":2,"a":1}':null}});
 tuple={request:t.request,request_digest:t.request_digest,...t.supported_requirements[0]};
 const sec=Math.floor(now/1000),purchase={network:NETWORK,asset:ASSET,payer,payTo,amount:'100000',validAfter:String(sec-1),validBefore:String(sec+299),authorization_nonce:'0x'+'b'.repeat(64)};
 const dispatch={schema_version:'ln_church.paid_service_trial_sample_dispatch_request.v3',...tuple,purchase};dispatch.operation_ref=sampleReferenceV2(dispatch);dispatch.signature=await account.signTypedData(purchaseTypedData(purchase));
 const pending=await samples.dispatch(dispatch),replay=await samples.dispatch(dispatch);
 await witnessSample(dispatch.operation_ref,purchase);
 const challenge=await sampleRead({rawPath:'/sample-recovery/challenge',httpMethod:'POST',body:JSON.stringify({schema_version:'ln_church.purchase_sample_read_challenge_request.v3',operation_ref:dispatch.operation_ref,payer})});
 const ch=JSON.parse(challenge.body),signature=await account.signTypedData(ch.typed_data);
 const read=await sampleRead({rawPath:'/sample-recovery/status',httpMethod:'POST',body:JSON.stringify({...ch,schema_version:'ln_church.purchase_sample_read_request.v3',signature})});
 const recovered=JSON.parse(read.body);
 const registration={schema_version:'ln_church.task_offer_create_request.paid_service_trial.v3',task_type:'paid_service_trial.v3',...tuple,sample_operation_ref:dispatch.operation_ref,sample_attachment_token:recovered.sample_attachment_token,plan_id:'C40',repeat_policy:'ALLOW_REPEAT'};
 const service=createPaidTrialRegistrationService({store:h.store,samples,clock,chainReadback:async i=>finality(i)});
 const handler=gateway.createPaidTrialRegistrationHandler({serviceFactory:async()=>service,payTo:()=>payTo,reconcile:id=>service.reconcile(id),gate:async()=>{},assertFacilitatorReady:async()=>{},providerClient:{verify:async()=>({isValid:true,payer}),settle:async()=>{feeSettles++;return {success:true,network:NETWORK,transaction:hash,payer};}}});
 const fee=paidRegistrationChallenge(registration,{payTo}),fp={...purchase,amount:fee.requirements.amount,authorization_nonce:'0x'+'c'.repeat(64)},fs=await account.signTypedData(purchaseTypedData(fp));
 const authorization=Object.fromEntries(Object.entries(purchaseTypedData(fp).message).map(([k,v])=>[k,typeof v==='bigint'?String(v):v]));
 const header=Buffer.from(JSON.stringify({x402Version:2,resource:fee.resource,accepted:fee.requirements,payload:{authorization,signature:fs}})).toString('base64');
 const ctx={get:()=>registration,req:{header:n=>n.toLowerCase()==='payment-signature'?header:undefined,method:'POST',path:'/bazaar/task-offers'},json:(body,status,headers)=>({body,status,headers})};
 const out=await withRegistrationTiming({budgetValid:true,deadline:Date.now()+120000},()=>handler(ctx));if(out.status!==200)throw Error('Registration '+JSON.stringify(out));
 taskId=out.body.task_id;
 const lookup=createRegistrationReadLookup({getKey:i=>h.store.getKey({table:'tasks',...i})});
 const retained=await lookup({profile:'V185_PAID_SERVICE_TRIAL',operationRef:out.body.registration_intent_id,payer});
 return {task:taskProjection(await h.store.get(taskId),now),registration:out.body,retained,terms:t,pending:pending.body,replay:replay.body,recovered,samplePaid,feeSettles};
}
async function run(x){
 if(x.control==='setup')return setup(x.method);
 if(x.control==='counts')return {now,samplePaid,agentPaid,feeSettles};
 if(x.control==='advance'){now+=x.ms;return {now};}
 if(x.control==='seller'){
  if(JSON.stringify(x.request)!==JSON.stringify(tuple.request))throw Error('Request changed');
  if(!x.payment)return {status:402,headers:Object.entries(seller().headers),body:''};
  const payload=JSON.parse(Buffer.from(x.payment,'base64')),a=payload.payload.authorization;
  purchased={network:NETWORK,asset:ASSET,payer:a.from.toLowerCase(),payTo:a.to.toLowerCase(),amount:a.value,validAfter:a.validAfter,validBefore:a.validBefore,authorization_nonce:a.nonce};
  if(purchased.amount!=='100000'||(await viem.recoverTypedDataAddress({...purchaseTypedData(purchased),signature:payload.payload.signature})).toLowerCase()!==payer)throw Error('Wrong full-amount signature');
  agentPaid++;return {status:200,headers:[],body:'synthetic seller response'};
 }
 if(x.control==='verify'){
  const e=await h.store.get(taskId,'EXEC#'+x.execution);
  const w=await verifyExternalPurchase({rpc:chain(purchased,now),purchase:e.report.purchase,transactionHash:hash,termsDigest:e.terms_digest,claimAcceptedAt:e.claim_accepted_at});
  const bad=await verifyExternalPurchase({rpc:chain({...purchased,amount:'10000'},now),purchase:e.report.purchase,transactionHash:hash,termsDigest:e.terms_digest,claimAcceptedAt:e.claim_accepted_at});
  await h.store.transact([{put:{...e,version:e.version+1,witness:{...w,report_sha256:e.report_sha256,observed_at:new Date(now).toISOString()}},expectedVersion:e.version}]);
  const result=await evaluation.finalize(taskId,e.execution_id);return {state:w.state,bad:bad.state,reason:bad.reason,evaluation:result.evaluation_state};
 }
 if(x.control==='import'){
  const body=x.body,out=await samples.import(body),p={...purchased,authorization_nonce:'0x'+'f'.repeat(64)};
  return {pending:out.body,result:await witnessSample(out.body.operation_ref,p)};
 }
 const m=x.path.match(/^\/api\/agent\/tasks\/([^/]+)(.*)$/);
 if(x.path==='/api/agent/tasks')return {status:200,body:{schema_version:'ln_church.agent_task_page.paid_service_trial.v3',tasks:[taskProjection(await h.store.get(taskId),now)],next_cursor:null}};
 if(!m)throw Error('Unsupported SDK route');
 if(!m[2])return {status:200,body:taskProjection(await h.store.get(m[1]),now)};
 const sub=m[2].match(/^\/submissions\/([^/]+)\/status$/),op=sub?'status':m[2]==='/claim'?'claim':'report';
 return createPaidExecutionHandler(execution,op,3)({rawPath:x.path,httpMethod:x.method,body:x.body,headers:x.headers,pathParameters:{task_id:m[1],...(sub?{submission_id:sub[1]}:{})}});
}
for await(const line of createInterface({input:process.stdin,crlfDelay:Infinity})){
 try{process.stdout.write(JSON.stringify(await run(JSON.parse(line)))+'\n');}
 catch(e){process.stdout.write(JSON.stringify({bridge_error:e.name,message:e.message,code:e.code??null})+'\n');}
}
