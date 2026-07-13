(function(){
  var storageKey='okoroleva_analytics_consent_v1';
  var counterId=105124237;

  function loadMetrika(){
    if(document.getElementById('ymTag')) return;
    window.ym=window.ym||function(){(window.ym.a=window.ym.a||[]).push(arguments)};
    window.ym.l=1*new Date();
    window.ym(counterId,'init',{
      accurateTrackBounce:true,
      trackLinks:true,
      clickmap:true,
      webvisor:true
    });
    var script=document.createElement('script');
    script.id='ymTag';
    script.async=true;
    script.src='https://mc.yandex.ru/metrika/tag.js';
    document.head.appendChild(script);
  }

  function remember(value){
    try{localStorage.setItem(storageKey,value)}catch(error){}
  }

  function showNotice(){
    if(document.querySelector('.cookie-consent')) return;
    var notice=document.createElement('aside');
    notice.className='cookie-consent';
    notice.setAttribute('role','dialog');
    notice.setAttribute('aria-label','Настройки аналитики');
    notice.innerHTML='<div class="cookie-consent__copy"><strong>Аналитика и cookie</strong><p>Сайт использует Яндекс.Метрику и Вебвизор, чтобы понимать, какие материалы полезны. Аналитика включится только с вашего согласия. <a href="/privacy-policy.html">Подробнее</a></p></div><div class="cookie-consent__actions"><button type="button" data-consent="reject">Только необходимые</button><button type="button" class="cookie-consent__accept" data-consent="accept">Разрешить аналитику</button></div>';
    notice.addEventListener('click',function(event){
      var button=event.target.closest('[data-consent]');
      if(!button) return;
      var accepted=button.getAttribute('data-consent')==='accept';
      remember(accepted?'accepted':'rejected');
      notice.remove();
      if(accepted) loadMetrika();
    });
    document.body.appendChild(notice);
  }

  var consent='';
  try{consent=localStorage.getItem(storageKey)||''}catch(error){}
  if(consent==='accepted'){
    if('requestIdleCallback' in window) requestIdleCallback(loadMetrika,{timeout:3000});
    else addEventListener('load',loadMetrika,{once:true});
  }else if(consent!=='rejected'){
    if(document.readyState==='loading') document.addEventListener('DOMContentLoaded',showNotice,{once:true});
    else showNotice();
  }
})();
