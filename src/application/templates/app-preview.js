// Runs on the app origin. Credentials never pass to the Dreamy parent page.
(() => {
  const key = 'dream.preview.request';
  // Embedded in a Dreamy preview, tell the parent where the app has navigated so
  // its address bar follows along; only the configured preview origins are told.
  const previewOrigins = __DREAM_PREVIEW_ORIGINS__;
  if (window.parent !== window && previewOrigins.length) {
    const report = () => { for (const origin of previewOrigins) { try { window.parent.postMessage({type:'dream-preview-location', href: location.href}, origin); } catch {} } };
    for (const method of ['pushState','replaceState']) { const original = history[method]; history[method] = function(...args) { const result = original.apply(this, args); setTimeout(report, 0); return result; }; }
    addEventListener('popstate', report); addEventListener('hashchange', report); addEventListener('DOMContentLoaded', report, {once:true}); report();
  }
  const read = () => { try { const value=JSON.parse(sessionStorage.getItem(key));return value && Date.now()-value.started<15*60*1000 ? value : null; } catch { return null; } };
  const post = async (path,body) => { const r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},credentials:'same-origin',body:JSON.stringify(body)});if(!r.ok)throw Error('Sign-in could not return to the preview. Please try again.');return r.json(); };
  window.dreamPreviewAuthenticate = (method,email) => {
    const nonce=Array.from(crypto.getRandomValues(new Uint8Array(32)),v=>v.toString(16).padStart(2,'0')).join('');
    const popup=window.open('/api/preview/auth#'+new URLSearchParams({nonce,method,email:email||''}), 'dream-preview-'+nonce, 'popup,width=520,height=760');
    if(!popup)return false;
    const listener=async event=>{
      if(event.origin!==location.origin || event.source!==popup || event.data?.type!=='dream-preview-session' || event.data.nonce!==nonce)return;
      window.removeEventListener('message',listener);
      try {await post('/api/preview/redeem',{nonce,code:event.data.code});location.replace('/');}
      catch(error){const notice=document.getElementById('notice');if(notice){notice.textContent=error.message;notice.hidden=false;}}
    };
    window.addEventListener('message',listener);
    const timer=setInterval(()=>{if(popup.closed){clearInterval(timer);window.removeEventListener('message',listener);}},1000);
    return true;
  };
  if(location.pathname==='/api/preview/auth'){
    const params=new URLSearchParams(location.hash.slice(1));history.replaceState(null,'',location.pathname);
    if(!window.opener || !/^[a-f0-9]{64}$/.test(params.get('nonce')||''))return;
    sessionStorage.setItem(key,JSON.stringify({nonce:params.get('nonce'),method:params.get('method'),email:params.get('email')||'',started:Date.now()}));
    location.replace('/api/login/');return;
  }
  const request=read();
  if(location.pathname==='/api/preview/finish'){
    if(!request || !window.opener)return;
    post('/api/preview/issue',{nonce:request.nonce}).then(({code})=>{
      window.opener.postMessage({type:'dream-preview-session',nonce:request.nonce,code},location.origin);
      sessionStorage.removeItem(key);window.close();
    }).catch(error=>{document.querySelector('p').textContent=error.message;});return;
  }
  if(window.top===window && request && !location.pathname.startsWith('/api/')){location.replace('/api/preview/finish');return;}
  if(window.top===window && request && location.pathname==='/api/login/'){
    // An email link may finish in another tab. This popup sees that first-party
    // session and completes the same one-use handoff to the embedded app.
    const timer=setInterval(async()=>{
      try{const response=await fetch('/api/admin/users/me/',{credentials:'same-origin',cache:'no-store'});if(response.ok){clearInterval(timer);location.replace('/api/preview/finish');}}catch{}
    },2000);
    addEventListener('DOMContentLoaded',()=>{
      const method=request.method;request.method='';sessionStorage.setItem(key,JSON.stringify(request));
      if(method==='google' && !new URLSearchParams(location.search).has('google_error'))location.replace('/api/auth/google');
      else if(method==='email' && request.email){document.getElementById('email').value=request.email;document.getElementById('email-form').requestSubmit();}
    },{once:true});
  }
})();
