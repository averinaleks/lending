(function(){
  const progress=document.querySelector('.progress');
  const update=()=>{const h=document.documentElement.scrollHeight-innerHeight;progress?.style.setProperty('--p',h?Math.min(1,scrollY/h):0)};
  update();addEventListener('scroll',update,{passive:true});
  const menu=document.querySelector('.menu-toggle'),nav=document.querySelector('#menu');
  menu?.addEventListener('click',()=>{const open=menu.getAttribute('aria-expanded')==='true';menu.setAttribute('aria-expanded',String(!open));nav?.classList.toggle('is-open',!open)});
  nav?.querySelectorAll('a').forEach(a=>a.addEventListener('click',()=>{nav.classList.remove('is-open');menu?.setAttribute('aria-expanded','false')}));
  addEventListener('keydown',e=>{if(e.key==='Escape'&&nav?.classList.contains('is-open')){nav.classList.remove('is-open');menu?.setAttribute('aria-expanded','false');menu?.focus()}});
  const items=document.querySelectorAll('.reveal');
  if(!('IntersectionObserver'in window)||matchMedia('(prefers-reduced-motion: reduce)').matches){items.forEach(x=>x.classList.add('is-visible'));return}
  const observer=new IntersectionObserver(entries=>entries.forEach(e=>{if(e.isIntersecting){e.target.classList.add('is-visible');observer.unobserve(e.target)}}),{threshold:.08,rootMargin:'0px 0px -5%'});
  document.documentElement.classList.add('motion-ready');
  items.forEach(x=>observer.observe(x));
})();


(function(){const button=document.createElement('button');button.type='button';button.className='back-to-top';button.setAttribute('aria-label','Наверх');button.textContent='↑';document.body.appendChild(button);const sync=()=>button.classList.toggle('is-visible',window.scrollY>600);sync();window.addEventListener('scroll',sync,{passive:true});button.addEventListener('click',()=>window.scrollTo({top:0,behavior:window.matchMedia('(prefers-reduced-motion: reduce)').matches?'auto':'smooth'}));})();
