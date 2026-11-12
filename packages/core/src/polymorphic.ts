import * as crypto from 'node:crypto';

/**
 * Encodes a UTF-8 string into an array of XOR-masked byte values using an 8-byte key.
 */
function xorEncodeString(input: string, keyBytes: Buffer): number[] {
  const bytes = Buffer.from(input, 'utf8');
  const encoded: number[] = new Array(bytes.length);
  for (let i = 0; i < bytes.length; i++) {
    encoded[i] = bytes[i] ^ keyBytes[i % keyBytes.length];
  }
  return encoded;
}

/**
 * Generates a unique randomized JS identifier prefix (`_ol_<hex>`).
 */
function randomIdentifier(prefix = '_ol_'): string {
  return `${prefix}${crypto.randomBytes(4).toString('hex')}`;
}

/**
 * Strips PEM headers/footers and whitespace to yield raw Base64 SPKI key material.
 */
export function stripPemHeaders(pem: string): string {
  return pem
    .replace(/-----BEGIN [A-Z0-9 ]+-----/g, '')
    .replace(/-----END [A-Z0-9 ]+-----/g, '')
    .replace(/\s+/g, '');
}

/**
 * Generates a polymorphic, self-executing browser probe (IIFE) with per-request
 * 8-byte XOR string masking and randomized AST variable identifiers.
 *
 * Collects ground-truth DOM origin telemetry, computes Canvas/WebGL hardware hashes,
 * measures round-trip application latency, checks native WebCrypto prototype integrity,
 * and encrypts the payload using the server's RSA-2048 SPKI Public Key (RSA-OAEP SHA-256
 * hybrid envelope) via `window.crypto.subtle`.
 */
export function generatePolymorphicClientScript(
  publicKeyPem: string,
  nonce: string,
  pingEndpoint = '/api/ping',
  challengeProof = ''
): string {
  const xorKey = crypto.randomBytes(8);
  const xorKeyLiteral = `[${Array.from(xorKey).join(',')}]`;
  const affineOffset = 17 + (xorKey[0] % 37);

  const proofStr = challengeProof || '';
  const halfLen = Math.floor(proofStr.length / 2);
  const proofHalfA = proofStr.slice(0, halfLen);
  const proofHalfB = proofStr.slice(halfLen);

  const encodedProofA = xorEncodeString(proofHalfA, xorKey).map((b) => b + affineOffset);
  const encodedProofB = xorEncodeString(proofHalfB, xorKey).map((b) => b + affineOffset);

  const idKey = randomIdentifier('_k_');
  const idDecode = randomIdentifier('_dec_');
  const idPemB64 = randomIdentifier('_pk_');
  const idNonce = randomIdentifier('_nc_');
  const idProofOverride = randomIdentifier('_pf_');
  const idPingUrl = randomIdentifier('_pg_');
  const idCanvasFn = randomIdentifier('_cv_');
  const idWebglFn = randomIdentifier('_gl_');
  const idIntegrityFn = randomIdentifier('_in_');
  const idSynthProofFn = randomIdentifier('_sp_');
  const idRttFn = randomIdentifier('_rt_');
  const idB64ToBuf = randomIdentifier('_b2a_');
  const idBufToB64 = randomIdentifier('_a2b_');
  const idBuildToken = randomIdentifier('_tk_');
  const idHookForms = randomIdentifier('_hf_');
  const idCachedToken = randomIdentifier('_ct_');

  const encLocation = JSON.stringify(xorEncodeString('location', xorKey));
  const encHostname = JSON.stringify(xorEncodeString('hostname', xorKey));
  const encOrigin = JSON.stringify(xorEncodeString('origin', xorKey));
  const encPort = JSON.stringify(xorEncodeString('port', xorKey));
  const encPathname = JSON.stringify(xorEncodeString('pathname', xorKey));
  const encReferrer = JSON.stringify(xorEncodeString('referrer', xorKey));
  const encUserAgent = JSON.stringify(xorEncodeString('userAgent', xorKey));
  const encWebdriver = JSON.stringify(xorEncodeString('webdriver', xorKey));
  const encCrypto = JSON.stringify(xorEncodeString('crypto', xorKey));
  const encSubtle = JSON.stringify(xorEncodeString('subtle', xorKey));
  const encRsaOaep = JSON.stringify(xorEncodeString('RSA-OAEP', xorKey));
  const encSha256 = JSON.stringify(xorEncodeString('SHA-256', xorKey));
  const encAesGcm = JSON.stringify(xorEncodeString('AES-GCM', xorKey));
  const encSpki = JSON.stringify(xorEncodeString('spki', xorKey));
  const encRaw = JSON.stringify(xorEncodeString('raw', xorKey));
  const encImportKey = JSON.stringify(xorEncodeString('importKey', xorKey));
  const encEncrypt = JSON.stringify(xorEncodeString('encrypt', xorKey));

  const cleanSpkiBase64 = stripPemHeaders(publicKeyPem);
  const safeNonce = JSON.stringify(nonce);
  const safePing = JSON.stringify(pingEndpoint);

  return `(function(){
  "use strict";
  var ${idKey}=${xorKeyLiteral};
  function ${idDecode}(arr){
    var out="";
    for(var i=0;i<arr.length;i++){
      out+=String.fromCharCode(arr[i]^${idKey}[i%${idKey}.length]);
    }
    return out;
  }
  var ${idPemB64}=${JSON.stringify(cleanSpkiBase64)};
  var ${idNonce}=${safeNonce};
  var ${idProofOverride}=null;
  var ${idPingUrl}=${safePing};
  var ${idCachedToken}=null;

  function ${idSynthProofFn}(){
    if(${idProofOverride})return ${idProofOverride};
    var pA=${JSON.stringify(encodedProofA)}.map(function(v){return v-${affineOffset};});
    var pB=${JSON.stringify(encodedProofB)}.map(function(v){return v-${affineOffset};});
    return ${idDecode}(pA)+${idDecode}(pB);
  }

  function ${idB64ToBuf}(b64){
    var bin=window.atob(b64);
    var len=bin.length;
    var bytes=new Uint8Array(len);
    for(var i=0;i<len;i++){bytes[i]=bin.charCodeAt(i);}
    return bytes.buffer;
  }

  function ${idBufToB64}(buf){
    var bytes=new Uint8Array(buf);
    var bin="";
    for(var i=0;i<bytes.byteLength;i++){bin+=String.fromCharCode(bytes[i]);}
    return window.btoa(bin);
  }

  function ${idIntegrityFn}(){
    try{
      var cObj=window[${idDecode}(${encCrypto})];
      var sObj=cObj&&cObj[${idDecode}(${encSubtle})];
      if(!sObj)return false;
      var toStr=Function.prototype.toString;
      function chk(fn,expectedName){
        if(typeof fn!=="function")return false;
        if(Object.prototype.hasOwnProperty.call(fn,"prototype"))return false;
        var nm=String(fn.name||"");
        if(nm.indexOf("bound ")===0||(expectedName&&nm!==expectedName))return false;
        var src=toStr.call(fn);
        return src.indexOf("[native code]")!==-1;
      }
      if(!chk(toStr,"toString"))return false;
      if(!chk(sObj[${idDecode}(${encEncrypt})],${idDecode}(${encEncrypt})))return false;
      if(!chk(JSON.stringify,"stringify"))return false;
      if(typeof TextEncoder!=="undefined"&&!chk(TextEncoder.prototype.encode,"encode"))return false;
      return true;
    }catch(_e){
      return false;
    }
  }

  function ${idCanvasFn}(){
    try{
      var c=document.createElement("canvas");
      c.width=220;c.height=48;
      var ctx=c.getContext("2d");
      if(!ctx)return "no-canvas-context";
      ctx.textBaseline="alphabetic";
      ctx.fillStyle="#10b981";
      ctx.fillRect(12,4,96,24);
      ctx.fillStyle="#0f172a";
      ctx.font="14px monospace";
      ctx.fillText("OriginLock::NullFilter#2048",6,22);
      ctx.strokeStyle="#38bdf8";
      ctx.beginPath();
      ctx.arc(160,24,14,0,Math.PI*2,true);
      ctx.stroke();
      var raw=c.toDataURL();
      var h=0x811c9dc5;
      for(var i=0;i<raw.length;i++){
        h^=raw.charCodeAt(i);
        h=Math.imul(h,0x01000193)>>>0;
      }
      var h2=0x811c9dc5;
      for(var j=raw.length-1;j>=0;j--){
        h2^=raw.charCodeAt(j);
        h2=Math.imul(h2,0x01000193)>>>0;
      }
      return ("00000000"+h.toString(16)).slice(-8)+("00000000"+h2.toString(16)).slice(-8);
    }catch(_e){
      return "canvas-blocked";
    }
  }

  function ${idWebglFn}(){
    try{
      var c=document.createElement("canvas");
      var gl=c.getContext("webgl")||c.getContext("experimental-webgl");
      if(!gl)return "webgl-unavailable";
      var dbg=gl.getExtension("WEBGL_debug_renderer_info");
      if(dbg){
        return String(gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL)||"webgl-masked");
      }
      return String(gl.getParameter(gl.RENDERER)||"webgl-default");
    }catch(_e){
      return "webgl-error";
    }
  }

  async function ${idRttFn}(){
    var t0=performance.now();
    try{
      await fetch(${idPingUrl},{method:"HEAD",cache:"no-store",credentials:"same-origin"});
      return Math.max(1,Math.round(performance.now()-t0));
    }catch(_e){
      return Math.max(1,Math.round(performance.now()-t0));
    }
  }

  async function ${idBuildToken}(){
    var locProp=${idDecode}(${encLocation});
    var locObj=window[locProp];
    var rtt=await ${idRttFn}();
    var synthProof=${idSynthProofFn}();
    var payload={
      hostname:String(locObj[${idDecode}(${encHostname})]||""),
      origin:String(locObj[${idDecode}(${encOrigin})]||""),
      port:String(locObj[${idDecode}(${encPort})]||""),
      pathname:String(locObj[${idDecode}(${encPathname})]||"/"),
      referrer:String(document[${idDecode}(${encReferrer})]||""),
      userAgent:String(navigator[${idDecode}(${encUserAgent})]||""),
      webdriver:Boolean(navigator[${idDecode}(${encWebdriver})]),
      canvasHash:${idCanvasFn}(),
      webglRenderer:${idWebglFn}(),
      domIntegrityValid:${idIntegrityFn}(),
      challengeProof:synthProof||undefined,
      rttMs:rtt,
      clientTimestamp:Date.now(),
      nonce:${idNonce}
    };

    var cObj=window[${idDecode}(${encCrypto})];
    var subtle=cObj[${idDecode}(${encSubtle})];
    var importKeyName=${idDecode}(${encImportKey});
    var encryptName=${idDecode}(${encEncrypt});
    var rsaAlgName=${idDecode}(${encRsaOaep});
    var shaAlgName=${idDecode}(${encSha256});
    var aesAlgName=${idDecode}(${encAesGcm});

    var spkiBuf=${idB64ToBuf}(${idPemB64});
    var rsaPubKey=await subtle[importKeyName](
      ${idDecode}(${encSpki}),
      spkiBuf,
      {name:rsaAlgName,hash:{name:shaAlgName}},
      false,
      [encryptName]
    );

    var aesRawKey=new Uint8Array(32);
    var ivBytes=new Uint8Array(12);
    cObj.getRandomValues(aesRawKey);
    cObj.getRandomValues(ivBytes);

    var aesCryptoKey=await subtle[importKeyName](
      ${idDecode}(${encRaw}),
      aesRawKey.buffer,
      {name:aesAlgName},
      false,
      [encryptName]
    );

    var encodedJson=new TextEncoder().encode(JSON.stringify(payload));
    var gcmCipherBuf=await subtle[encryptName](
      {name:aesAlgName,iv:ivBytes},
      aesCryptoKey,
      encodedJson
    );

    var keyAndIv=new Uint8Array(44);
    keyAndIv.set(aesRawKey,0);
    keyAndIv.set(ivBytes,32);

    var rsaKeyCipherBuf=await subtle[encryptName](
      {name:rsaAlgName},
      rsaPubKey,
      keyAndIv.buffer
    );

    var rsaBytes=new Uint8Array(rsaKeyCipherBuf);
    var gcmBytes=new Uint8Array(gcmCipherBuf);
    var combined=new Uint8Array(rsaBytes.byteLength+gcmBytes.byteLength);
    combined.set(rsaBytes,0);
    combined.set(gcmBytes,rsaBytes.byteLength);

    ${idCachedToken}=${idBufToB64}(combined.buffer);
    return ${idCachedToken};
  }

  function ${idHookForms}(){
    var forms=document.querySelectorAll('form[data-originlock="true"],form[data-nullfilter="true"]');
    for(var i=0;i<forms.length;i++){
      (function(formEl){
        if(formEl.getAttribute("data-ol-bound")==="1")return;
        formEl.setAttribute("data-ol-bound","1");
        var hiddenInput=formEl.querySelector('input[name="_originlock_token"]');
        if(!hiddenInput){
          hiddenInput=document.createElement("input");
          hiddenInput.type="hidden";
          hiddenInput.name="_originlock_token";
          formEl.appendChild(hiddenInput);
        }
        ${idBuildToken}().then(function(tok){
          hiddenInput.value=tok;
        }).catch(function(){});
        formEl.addEventListener("submit",function(ev){
          if(!hiddenInput.value){
            ev.preventDefault();
            ${idBuildToken}().then(function(tok){
              hiddenInput.value=tok;
              HTMLFormElement.prototype.submit.call(formEl);
            }).catch(function(){
              HTMLFormElement.prototype.submit.call(formEl);
            });
          }
        });
      })(forms[i]);
    }
  }

  var api={
    getToken:function(){return ${idBuildToken}();},
    getCachedToken:function(){return ${idCachedToken};},
    setNonce:function(nextNonce,nextProof){
      if(typeof nextNonce==="string"&&nextNonce.length>0){
        ${idNonce}=nextNonce;
        if(typeof nextProof==="string")${idProofOverride}=nextProof;
        ${idCachedToken}=null;
      }
    },
    refreshHook:${idHookForms},
    probeId:${JSON.stringify(idBuildToken)},
    xorKeyHex:${JSON.stringify(xorKey.toString('hex'))}
  };
  window.__OriginLock=api;
  window.__NullFilter=api;

  if(document.readyState==="loading"){
    document.addEventListener("DOMContentLoaded",${idHookForms});
  }else{
    ${idHookForms}();
  }
})();`;
}
